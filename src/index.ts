import crypto from "crypto";
import express from "express";
import session from "express-session";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import { z } from "zod";
import {
  CONFIG,
  SUPPORTED_SCOPES,
} from "./config";
import {
  createClient,
  createUser,
  ensureDefaultApp,
  findAppByResource,
  findClientById,
  findClientByRegistrationAccessToken,
  findRefreshToken,
  findUserByEmail,
  findUserByUuid,
  persistAuthorizationCode,
  consumeAuthorizationCode,
  revokeRefreshToken,
  storeAccessToken,
  storeRefreshToken,
  validateScopes,
} from "./store";
import { initializeKeys, getJwks } from "./keyManager";
import {
  issueAccessToken,
  issueIdToken,
  createRefreshToken,
  verifyAccessToken,
} from "./tokens";

const app = express();
app.set("trust proxy", 1);

const hashPassword = (password: string) => bcrypt.hashSync(password, 12);
const verifyPassword = (password: string, hash: string) =>
  bcrypt.compareSync(password, hash);

const authorizationServerMetadata = {
  issuer: CONFIG.issuer,
  authorization_endpoint: `${CONFIG.issuer}/oauth/authorize`,
  token_endpoint: `${CONFIG.issuer}/oauth/token`,
  jwks_uri: `${CONFIG.issuer}/oauth/jwks`,
  registration_endpoint: `${CONFIG.issuer}/oauth/register`,
  response_types_supported: ["code"],
  grant_types_supported: ["authorization_code", "refresh_token"],
  code_challenge_methods_supported: ["S256"],
  token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
  scopes_supported: SUPPORTED_SCOPES,
};

app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: CONFIG.sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: CONFIG.baseUrl.startsWith("https://"),
    },
  })
);

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const renderPage = (title: string, body: string): string => `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>${title}</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.5; }
      form { max-width: 420px; margin-top: 1.5rem; display: flex; flex-direction: column; gap: 0.75rem; }
      label { display: flex; flex-direction: column; font-weight: 600; }
      input, select { padding: 0.5rem; font-size: 1rem; }
      button { padding: 0.65rem 1rem; font-size: 1rem; font-weight: 600; cursor: pointer; }
      .danger { color: #c0392b; }
      .scopes { margin: 1rem 0; padding: 1rem; background: #f6f8fa; border-radius: 0.5rem; }
      nav a { margin-right: 0.5rem; }
    </style>
  </head>
  <body>
    <nav>
      <a href="/">Home</a>
      <a href="/auth/login">Login</a>
      <a href="/auth/register">Register</a>
      <a href="/auth/logout">Logout</a>
    </nav>
    ${body}
  </body>
</html>
`;

const authorizationQuerySchema = z.object({
  response_type: z.literal("code"),
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  scope: z.string().min(1),
  state: z.string().optional(),
  code_challenge: z.string().min(43),
  code_challenge_method: z.literal("S256"),
  resource: z.string().url(),
});

type AuthorizationParams = z.infer<typeof authorizationQuerySchema>;

type PendingAuthRequest = {
  response_type: "code";
  client_id: string;
  redirect_uri: string;
  scope: string[];
  state?: string;
  code_challenge: string;
  code_challenge_method: "S256";
  resource: string;
};

class AuthorizationRequestError extends Error {
  status: number;
  title: string;
  body: string;

  constructor(status: number, title: string, body: string) {
    super(body);
    this.status = status;
    this.title = title;
    this.body = body;
  }
}

const prepareAuthorizationDetails = (params: AuthorizationParams) => {
  const client = findClientById(params.client_id);
  if (!client) {
    throw new AuthorizationRequestError(
      400,
      "Client error",
      `<p class="danger">Unknown client_id.</p>`
    );
  }
  if (!client.redirect_uris.includes(params.redirect_uri)) {
    throw new AuthorizationRequestError(
      400,
      "Redirect mismatch",
      `<p class="danger">redirect_uri is not registered for this client.</p>`
    );
  }
  const appRecord = findAppByResource(params.resource);
  if (!appRecord) {
    throw new AuthorizationRequestError(
      400,
      "Unknown resource",
      `<p class="danger">No app is registered for the requested resource: ${escapeHtml(
        params.resource
      )}</p>`
    );
  }
  const requestedScopes = params.scope.split(" ").filter(Boolean);
  const validScopes = validateScopes(requestedScopes);
  if (validScopes.length === 0) {
    throw new AuthorizationRequestError(
      400,
      "Invalid scope",
      `<p class="danger">Requested scopes are not supported.</p>`
    );
  }
  const authRequest: PendingAuthRequest = {
    response_type: params.response_type,
    client_id: params.client_id,
    redirect_uri: params.redirect_uri,
    scope: validScopes,
    state: params.state,
    code_challenge: params.code_challenge,
    code_challenge_method: params.code_challenge_method,
    resource: params.resource,
  };
  return { authRequest, client, app: appRecord };
};

const renderAuthorizePage = (
  authRequest: PendingAuthRequest,
  options: {
    clientName: string;
    appName?: string;
    error?: string;
    email?: string;
  }
) => {
  const scopeList = authRequest.scope
    .map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`)
    .join("");
  const errorBlock = options.error
    ? `<p class="danger">${escapeHtml(options.error)}</p>`
    : "";
  const emailValue = options.email ? ` value="${escapeHtml(options.email)}"` : "";
  const appBlock = options.appName
    ? `<p>App: <strong>${escapeHtml(options.appName)}</strong></p>`
    : "";
  const body = `
    <h1>Authorize ${escapeHtml(options.clientName)}</h1>
    ${appBlock}
    <p>Resource: <code>${escapeHtml(authRequest.resource)}</code></p>
    <div class="scopes">
      <p>The following scopes will be granted:</p>
      <ul>${scopeList}</ul>
    </div>
    ${errorBlock}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="response_type" value="${escapeHtml(
        authRequest.response_type
      )}" />
      <input type="hidden" name="client_id" value="${escapeHtml(
        authRequest.client_id
      )}" />
      <input type="hidden" name="redirect_uri" value="${escapeHtml(
        authRequest.redirect_uri
      )}" />
      <input type="hidden" name="scope" value="${escapeHtml(
        authRequest.scope.join(" ")
      )}" />
      <input type="hidden" name="code_challenge" value="${escapeHtml(
        authRequest.code_challenge
      )}" />
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(
        authRequest.code_challenge_method
      )}" />
      <input type="hidden" name="resource" value="${escapeHtml(
        authRequest.resource
      )}" />
      ${
        authRequest.state
          ? `<input type="hidden" name="state" value="${escapeHtml(
              authRequest.state
            )}" />`
          : ""
      }
      <label>Email
        <input type="email" name="email" required${emailValue} />
      </label>
      <label>Password
        <input type="password" name="password" required minlength="8" />
      </label>
      <div style="display:flex; gap:0.5rem;">
        <button type="submit" name="decision" value="approve">Sign in and Continue</button>
        <button type="submit" name="decision" value="deny">Cancel</button>
      </div>
    </form>
  `;
  return renderPage("Authorize access", body);
};

const issueCodeAndRedirect = (
  req: express.Request,
  res: express.Response,
  userUuid: string,
  authRequest: PendingAuthRequest
) => {
  const code = crypto.randomBytes(32).toString("base64url");
  const expiresAt = Math.floor(Date.now() / 1000) + 600;
  persistAuthorizationCode({
    code,
    user_uuid: userUuid,
    client_id: authRequest.client_id,
    redirect_uri: authRequest.redirect_uri,
    scope: authRequest.scope.join(" "),
    code_challenge: authRequest.code_challenge,
    code_challenge_method: authRequest.code_challenge_method,
    resource: authRequest.resource,
    expires_at: expiresAt,
    consumed: 0,
  });
  const redirect = new URL(authRequest.redirect_uri);
  redirect.searchParams.set("code", code);
  if (authRequest.state) {
    redirect.searchParams.set("state", authRequest.state);
  }
  req.session.authRequest = undefined;
  const finalize = () => res.redirect(redirect.toString());
  if (typeof req.session.save === "function") {
    req.session.save((err) => {
      if (err) {
        console.error("Failed to persist authorization session", err);
        return res
          .status(500)
          .send(
            renderPage(
              "Session error",
              `<p class="danger">We were unable to finalize the session. Please try again.</p>`
            )
          );
      }
      return finalize();
    });
    return;
  }
  finalize();
};

const authorizePostSchema = authorizationQuerySchema.extend({
  email: z.string().email().optional(),
  password: z.string().min(8).optional(),
  decision: z.enum(["approve", "deny"]).optional(),
});

const registrationSchema = z.object({
  redirect_uris: z.array(z.string().url()).min(1),
  client_name: z.string().optional(),
  application_type: z.enum(["web", "native"]).default("web"),
  grant_types: z
    .array(z.enum(["authorization_code", "refresh_token"]))
    .default(["authorization_code", "refresh_token"]),
  response_types: z.array(z.string()).optional(),
  token_endpoint_auth_method: z
    .enum(["none", "client_secret_post"])
    .default("none"),
  scope: z.string().optional(),
  resource: z.string().url().optional(),
});

const tokenRequestSchema = z.discriminatedUnion("grant_type", [
  z.object({
    grant_type: z.literal("authorization_code"),
    code: z.string(),
    redirect_uri: z.string().url(),
    client_id: z.string(),
    code_verifier: z.string(),
    resource: z.string().url().optional(),
    client_secret: z.string().optional(),
  }),
  z.object({
    grant_type: z.literal("refresh_token"),
    refresh_token: z.string(),
    client_id: z.string(),
    client_secret: z.string().optional(),
  }),
]);

app.get("/", (_req, res) => {
  res.send(
    renderPage(
      "OpenAI Apps Auth Server",
      `<h1>OpenAI Apps Auth Server</h1>
       <p>This server implements OAuth 2.1 + PKCE with dynamic client registration as required by the OpenAI Apps SDK.</p>
       <ul>
         <li><a href="/.well-known/oauth-protected-resource">Protected resource metadata</a></li>
         <li><a href="/.well-known/openid-configuration">OpenID configuration</a></li>
         <li><a href="/oauth/jwks">JWKS</a></li>
       </ul>`
    )
  );
});

app.get("/auth/login", (req, res) => {
  const body = `
    <h1>Login</h1>
    <form method="POST" action="/auth/login">
      <label>Email
        <input type="email" name="email" required />
      </label>
      <label>Password
        <input type="password" name="password" required />
      </label>
      <button type="submit">Sign in</button>
    </form>
    <p>No account yet? <a href="/auth/register">Register here</a>.</p>
  `;
  res.send(renderPage("Login", body));
});

app.post("/auth/login", (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .send(renderPage("Login failed", `<p class="danger">Invalid credentials.</p>`));
  }
  const { email, password } = parsed.data;
  const user = findUserByEmail(email.toLowerCase());
  if (!user || !verifyPassword(password, user.password_hash)) {
    return res
      .status(401)
      .send(renderPage("Login failed", `<p class="danger">Incorrect email or password.</p>`));
  }
  req.session.userUuid = user.uuid;
  return res.redirect("/");
});

app.get("/auth/register", (_req, res) => {
  const body = `
    <h1>Create your account</h1>
    <form method="POST" action="/auth/register">
      <label>Email
        <input type="email" name="email" required />
      </label>
      <label>Display name
        <input type="text" name="displayName" placeholder="Optional" />
      </label>
      <label>Password
        <input type="password" name="password" minlength="12" required />
      </label>
      <button type="submit">Create account</button>
    </form>
  `;
  res.send(renderPage("Register", body));
});

app.post("/auth/register", (req, res) => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(12),
    displayName: z.string().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .send(
        renderPage(
          "Registration failed",
          `<p class="danger">Please provide a valid email and a password of at least 12 characters.</p>`
        )
      );
  }
  const email = parsed.data.email.toLowerCase();
  if (findUserByEmail(email)) {
    return res
      .status(409)
      .send(
        renderPage(
          "Registration failed",
          `<p class="danger">This email address is already registered.</p>`
        )
      );
  }
  const passwordHash = hashPassword(parsed.data.password);
  const user = createUser(email, passwordHash, parsed.data.displayName);
  req.session.userUuid = user.uuid;
  return res.redirect("/");
});

app.get("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/oauth/authorize", (req, res) => {
  const parsed = authorizationQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    return res
      .status(400)
      .send(
        renderPage(
          "Invalid request",
          `<p class="danger">Malformed authorization request.</p>`
        )
      );
  }
  try {
    const { authRequest, client, app } = prepareAuthorizationDetails(
      parsed.data
    );
    req.session.authRequest = authRequest;
    const clientName = client.client_name ?? authRequest.client_id;

    if (req.session.userUuid) {
      const user = findUserByUuid(req.session.userUuid);
      if (user) {
        return issueCodeAndRedirect(req, res, user.uuid, authRequest);
      }
      req.session.userUuid = undefined;
    }

    return res.send(
      renderAuthorizePage(authRequest, {
        clientName,
        appName: app.name,
      })
    );
  } catch (error) {
    if (error instanceof AuthorizationRequestError) {
      return res
        .status(error.status)
        .send(renderPage(error.title, error.body));
    }
    console.error("Failed to process authorization request", error);
    return res
      .status(500)
      .send(
        renderPage(
          "Server error",
          `<p class="danger">An unexpected error occurred.</p>`
        )
      );
  }
});

app.post("/oauth/authorize", (req, res) => {
  const parsed = authorizePostSchema.safeParse(req.body);
  if (!parsed.success) {
    const sessionAuth = req.session.authRequest;
    if (sessionAuth) {
      const client = findClientById(sessionAuth.client_id);
      const appRecord = findAppByResource(sessionAuth.resource);
      return res
        .status(400)
        .send(
          renderAuthorizePage(sessionAuth, {
            clientName: client?.client_name ?? sessionAuth.client_id,
            appName: appRecord?.name,
            error: "Invalid submission. Please review the form and try again.",
            email:
              typeof req.body.email === "string"
                ? req.body.email
                : undefined,
          })
        );
    }
    return res
      .status(400)
      .send(
        renderPage(
          "Invalid request",
          `<p class="danger">Malformed authorization request.</p>`
        )
      );
  }

  const { decision, email, password, ...oauthParams } = parsed.data;

  try {
    const { authRequest, client, app } =
      prepareAuthorizationDetails(oauthParams);
    req.session.authRequest = authRequest;
    const clientName = client.client_name ?? authRequest.client_id;
    const appName = app.name;

    if (decision === "deny") {
      const redirect = new URL(authRequest.redirect_uri);
      redirect.searchParams.set("error", "access_denied");
      if (authRequest.state) {
        redirect.searchParams.set("state", authRequest.state);
      }
      req.session.authRequest = undefined;
      const finalize = () => res.redirect(redirect.toString());
      if (typeof req.session.save === "function") {
        req.session.save((err) => {
          if (err) {
            console.error("Failed to persist authorization session", err);
            return res
              .status(500)
              .send(
                renderPage(
                  "Session error",
                  `<p class="danger">We were unable to finalize the session. Please try again.</p>`
                )
              );
          }
          return finalize();
        });
        return;
      }
      return finalize();
    }

    if (!email || !password) {
      return res
        .status(400)
        .send(
          renderAuthorizePage(authRequest, {
            clientName,
            appName,
            error: "Please sign in to continue.",
            email,
          })
        );
    }

    const user = findUserByEmail(email.toLowerCase());
    if (!user || !verifyPassword(password, user.password_hash)) {
      return res
        .status(401)
        .send(
          renderAuthorizePage(authRequest, {
            clientName,
            appName,
            error: "Incorrect email or password.",
            email,
          })
        );
    }

    req.session.userUuid = user.uuid;
    // Optional: enforce purchase or entitlement checks here before issuing the code.
    return issueCodeAndRedirect(req, res, user.uuid, authRequest);
  } catch (error) {
    if (error instanceof AuthorizationRequestError) {
      return res
        .status(error.status)
        .send(renderPage(error.title, error.body));
    }
    console.error("Failed to process authorization submission", error);
    return res
      .status(500)
      .send(
        renderPage(
          "Server error",
          `<p class="danger">An unexpected error occurred.</p>`
        )
      );
  }
});

app.post("/oauth/token", async (req, res) => {
  const parsed = tokenRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Malformed token request.",
    });
  }
  const data = parsed.data;
  if (data.grant_type === "authorization_code") {
    const client = findClientById(data.client_id);
    if (!client) {
      return res
        .status(400)
        .json({ error: "invalid_client", error_description: "Unknown client_id." });
    }
    if (
      client.token_endpoint_auth_method === "client_secret_post" &&
      data.client_secret !== client.client_secret
    ) {
      return res
        .status(401)
        .json({ error: "invalid_client", error_description: "Client authentication failed." });
    }

    const codeRecord = consumeAuthorizationCode(data.code);
    if (!codeRecord) {
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "Authorization code not found or already used." });
    }
    if (codeRecord.expires_at < Math.floor(Date.now() / 1000)) {
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "Authorization code expired." });
    }
    if (codeRecord.client_id !== client.client_id) {
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "Authorization code was issued to a different client." });
    }
    if (codeRecord.redirect_uri !== data.redirect_uri) {
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "redirect_uri mismatch." });
    }
    if (data.resource && codeRecord.resource !== data.resource) {
      return res
        .status(400)
        .json({ error: "invalid_target", error_description: "Resource mismatch." });
    }
    const resource = codeRecord.resource;
    const digest = crypto
      .createHash("sha256")
      .update(data.code_verifier)
      .digest("base64url");
    if (digest !== codeRecord.code_challenge) {
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "code_verifier does not match code_challenge." });
    }
    const user = findUserByUuid(codeRecord.user_uuid);
    if (!user) {
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "User no longer exists." });
    }
    const { token: accessToken, expiresAt } = await issueAccessToken(
      user.uuid,
      client.client_id,
      resource,
      codeRecord.scope,
      user.email
    );
    storeAccessToken({
      token: accessToken,
      user_uuid: user.uuid,
      client_id: client.client_id,
      scope: codeRecord.scope,
      resource,
      expires_at: expiresAt,
    });
    const refresh = createRefreshToken();
    storeRefreshToken({
      token: refresh.token,
      user_uuid: user.uuid,
      client_id: client.client_id,
      scope: codeRecord.scope,
      resource,
      expires_at: refresh.expiresAt,
    });
    const scopeList = codeRecord.scope.split(" ").filter(Boolean);
    const response: Record<string, unknown> = {
      token_type: "Bearer",
      access_token: accessToken,
      expires_in: CONFIG.accessTokenTtlSeconds,
      scope: codeRecord.scope,
      refresh_token: refresh.token,
    };
    if (scopeList.includes("openid")) {
      const idToken = await issueIdToken(
        user.uuid,
        client.client_id,
        user.email
      );
      response.id_token = idToken.token;
    }
    return res.json(response);
  }

  if (data.grant_type === "refresh_token") {
    const client = findClientById(data.client_id);
    if (!client) {
      return res
        .status(400)
        .json({ error: "invalid_client", error_description: "Unknown client_id." });
    }
    if (
      client.token_endpoint_auth_method === "client_secret_post" &&
      data.client_secret !== client.client_secret
    ) {
      return res
        .status(401)
        .json({ error: "invalid_client", error_description: "Client authentication failed." });
    }
    const stored = findRefreshToken(data.refresh_token);
    if (!stored) {
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "Refresh token not found." });
    }
    if (stored.client_id !== client.client_id) {
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "Refresh token belongs to another client." });
    }
    if (stored.expires_at < Math.floor(Date.now() / 1000)) {
      revokeRefreshToken(data.refresh_token);
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "Refresh token expired." });
    }
    const user = findUserByUuid(stored.user_uuid);
    if (!user) {
      revokeRefreshToken(data.refresh_token);
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "User no longer exists." });
    }
    const { token: newAccessToken, expiresAt } = await issueAccessToken(
      user.uuid,
      client.client_id,
      stored.resource,
      stored.scope,
      user.email
    );
    storeAccessToken({
      token: newAccessToken,
      user_uuid: user.uuid,
      client_id: client.client_id,
      scope: stored.scope,
      resource: stored.resource,
      expires_at: expiresAt,
    });
    const refreshed = createRefreshToken();
    storeRefreshToken({
      token: refreshed.token,
      user_uuid: user.uuid,
      client_id: client.client_id,
      scope: stored.scope,
      resource: stored.resource,
      expires_at: refreshed.expiresAt,
    });
    revokeRefreshToken(data.refresh_token);
    return res.json({
      token_type: "Bearer",
      access_token: newAccessToken,
      expires_in: CONFIG.accessTokenTtlSeconds,
      scope: stored.scope,
      refresh_token: refreshed.token,
    });
  }

  return res.status(400).json({
    error: "unsupported_grant_type",
    error_description: "Grant type not supported.",
  });
});

app.post("/oauth/register", (req, res) => {
  const parsed = registrationSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "invalid_request", error_description: "Malformed registration payload." });
  }
  const data = parsed.data;
  const appRecord = data.resource
    ? findAppByResource(data.resource)
    : ensureDefaultApp();
  if (!appRecord) {
    return res
      .status(400)
      .json({ error: "invalid_target", error_description: "Unknown resource." });
  }
  const requestedScopeString = data.scope ?? appRecord.default_scopes;
  const requestedScopes = requestedScopeString.split(" ").filter(Boolean);
  const validScopes = validateScopes(requestedScopes);
  if (validScopes.length !== requestedScopes.length) {
    return res.status(400).json({
      error: "invalid_scope",
      error_description: "One or more requested scopes are not supported.",
    });
  }
  const scope = validScopes.join(" ");
  const client = createClient({
    client_name: data.client_name,
    application_type: data.application_type,
    grant_types: data.grant_types,
    redirect_uris: data.redirect_uris,
    scope,
    token_endpoint_auth_method: data.token_endpoint_auth_method,
    app_uuid: appRecord.uuid,
  });
  const response = {
    client_id: client.client_id,
    client_secret: client.client_secret,
    client_id_issued_at: client.client_id_issued_at,
    client_secret_expires_at: client.client_secret_expires_at,
    registration_access_token: client.registration_access_token,
    registration_client_uri: client.registration_client_uri,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    application_type: client.application_type,
    redirect_uris: client.redirect_uris,
    grant_types: client.grant_types,
    scope,
  };
  return res.status(201).json(response);
});

app.get("/oauth/client/:clientId", (req, res) => {
  const authHeader = req.header("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "invalid_client",
      error_description: "Missing registration access token.",
    });
  }
  const token = authHeader.slice("Bearer ".length);
  const client = findClientByRegistrationAccessToken(token);
  if (!client || client.client_id !== req.params.clientId) {
    return res.status(403).json({
      error: "access_denied",
      error_description: "Registration access token is invalid for this client.",
    });
  }
  return res.json({
    client_id: client.client_id,
    client_name: client.client_name,
    redirect_uris: client.redirect_uris,
    grant_types: client.grant_types,
    application_type: client.application_type,
    scope: client.scope,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
  });
});

app.get("/oauth/userinfo", async (req, res) => {
  const authHeader = req.header("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    res.setHeader(
      "WWW-Authenticate",
      `Bearer realm="apps-auth", error="invalid_token"`
    );
    return res.status(401).json({ error: "invalid_token" });
  }
  const token = authHeader.slice("Bearer ".length);
  try {
    const payload = await verifyAccessToken(token);
    const user = findUserByUuid(payload.sub);
    if (!user) {
      return res.status(404).json({ error: "user_not_found" });
    }
    return res.json({
      sub: user.uuid,
      email: user.email,
      email_verified: true,
      scope: payload.scope,
    });
  } catch (error) {
    res.setHeader(
      "WWW-Authenticate",
      `Bearer realm="apps-auth", error="invalid_token"`
    );
    return res.status(401).json({ error: "invalid_token" });
  }
});

app.get("/.well-known/openid-configuration", (_req, res) => {
  res.json({
    ...authorizationServerMetadata,
    userinfo_endpoint: `${CONFIG.issuer}/oauth/userinfo`,
    subject_types_supported: ["public"],
    claims_supported: ["sub", "email"],
    service_documentation: CONFIG.docsUrl,
  });
});

app.get("/.well-known/oauth-authorization-server", (_req, res) => {
  res.json(authorizationServerMetadata);
});

app.get("/.well-known/oauth-protected-resource", (_req, res) => {
  res.json({
    resource: CONFIG.resourceServerUrl,
    authorization_servers: [CONFIG.issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: SUPPORTED_SCOPES,
    resource_documentation: CONFIG.docsUrl,
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    policy_uri: CONFIG.docsUrl,
    contacts: [CONFIG.adminContact],
  });
});

app.get("/oauth/jwks", (_req, res) => {
  res.json(getJwks());
});

app.get("/mcp/ping", async (req, res) => {
  const authHeader = req.header("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    res.setHeader(
      "WWW-Authenticate",
      `Bearer realm="apps-auth", authorization_uri="${CONFIG.issuer}/.well-known/oauth-protected-resource"`
    );
    return res.status(401).json({ error: "missing_token" });
  }
  const token = authHeader.slice("Bearer ".length);
  try {
    const payload = await verifyAccessToken(token);
    return res.json({
      status: "ok",
      user: payload.sub,
      scopes: payload.scope,
      resource: payload.aud,
    });
  } catch (error) {
    res.setHeader(
      "WWW-Authenticate",
      `Bearer realm="apps-auth", authorization_uri="${CONFIG.issuer}/.well-known/oauth-protected-resource", error="invalid_token"`
    );
    return res.status(401).json({ error: "invalid_token" });
  }
});

const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;

const start = async () => {
  ensureDefaultApp();
  await initializeKeys();
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`Auth server listening on ${CONFIG.baseUrl} (port ${PORT})`);
  });
};

start().catch((err) => {
  console.error("Failed to start auth server", err);
  process.exit(1);
});
