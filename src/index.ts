import crypto from "crypto";
import https from "https";
import express from "express";
import session from "express-session";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { decodeProtectedHeader } from "jose";
import { CONFIG } from "./config";
import {
  createClient,
  createUser,
  findAppByUuid,
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
  getAppScopes,
  getAllSupportedScopes,
  listApps,
  canonicalizeScopes,
  userHasActivePayment,
  moveClientToApp,
} from "./store";
import type { App, Client, AppMetaInfo, AppPaymentModel } from "./store";
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
const createRandomPassword = () => crypto.randomBytes(24).toString("hex");

const serializeForScript = (value: unknown): string =>
  JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026");

const buildAuthorizationServerMetadata = async () => {
  const scopes = await getAllSupportedScopes();
  return {
    issuer: CONFIG.issuer,
    authorization_endpoint: `${CONFIG.issuer}/oauth/authorize`,
    token_endpoint: `${CONFIG.issuer}/oauth/token`,
    jwks_uri: `${CONFIG.issuer}/oauth/jwks`,
    registration_endpoint: `${CONFIG.issuer}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
    scopes_supported: scopes,
  };
};

const buildResourceMetadata = (app: App) => ({
  resource: app.resource_uri,
  authorization_servers: [CONFIG.issuer],
  bearer_methods_supported: ["header"],
  scopes_supported: getAppScopes(app),
  resource_documentation: CONFIG.docsUrl,
  token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
  policy_uri: CONFIG.docsUrl,
  contacts: [CONFIG.adminContact],
});

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

app.use((req, res, next) => {
  const start = Date.now();
  const { method, originalUrl } = req;
  const requestDetails = buildRequestLogDetails(req);
  if (Object.keys(requestDetails).length > 0) {
    logHttpEvent(method, originalUrl, "request", requestDetails);
  } else {
    logHttpEvent(method, originalUrl, "request");
  }

  res.on("finish", () => {
    const responseDetails: RouteLogDetails = {
      status: res.statusCode,
      durationMs: Date.now() - start,
    };
    if (res.getHeader("x-request-id")) {
      responseDetails.requestId = res.getHeader("x-request-id");
    }
    logHttpEvent(method, originalUrl, "response", responseDetails);
  });

  res.on("error", (error) => {
    const errorDetails: RouteLogDetails = {
      status: res.statusCode,
      error: error instanceof Error ? error.message : error,
    };
    logHttpEvent(method, originalUrl, "error", errorDetails);
  });

  next();
});

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

type RenderOptions = {
  scripts?: string;
};

type AuthResumePayload = {
  response_type: "code";
  client_id: string;
  redirect_uri: string;
  scope: string;
  state?: string;
  code_challenge: string;
  code_challenge_method: "S256";
  resource: string;
};

type LandingPageContent = {
  app: {
    name: string;
    description: string;
    tagline?: string;
  };
  features: Array<{
    title: string;
    description: string;
  }>;
  howItWorks: Array<{
    question: string;
    answer: string;
  }>;
};

const trimOrUndefined = (value?: string): string | undefined => {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
};

const defaultAppName = "Smart App Name";
const defaultAppDescription =
  "One sentence introducing your app's core value, helping users quickly understand the product advantages";

const defaultFeatureCards: Array<{ title: string; description: string }> = [
  {
    title: "Smart Analysis",
    description:
      "Based on advanced AI technology, providing deep insights and intelligent recommendations",
  },
  {
    title: "Fast Response",
    description:
      "Millisecond-level response speed, instantly getting the information and answers you need",
  },
  {
    title: "Secure & Reliable",
    description:
      "Enterprise-level security protection, safeguarding your data privacy and information security",
  },
  {
    title: "Continuous Optimization",
    description:
      "Continuously learning and improving, providing increasingly accurate service experience",
  },
];

const defaultHowItWorksEntries: Array<{ question: string; answer: string }> = [
  {
    question: "How do I start using Smart App Name?",
    answer:
      "Sign in with your preferred identity provider, connect the data sources you care about, and pick the goals you want to track.",
  },
  {
    question: "What happens after I connect my data?",
    answer:
      "Smart App Name ingests your information in real time, highlights the most important trends, and prepares ready-to-share insights and action plans.",
  },
  {
    question: "How does Smart App Name keep recommendations fresh?",
    answer:
      "The assistant continuously learns from new activity and your feedback, automatically tuning future suggestions to stay aligned with your objectives.",
  },
];

const deriveLandingPageContent = (
  metaInfo?: AppMetaInfo
): LandingPageContent => {
  const chatMeta = metaInfo?.chatAppMeta;
  const appName = trimOrUndefined(chatMeta?.name) ?? defaultAppName;
  const appDescription =
    trimOrUndefined(chatMeta?.description) ?? defaultAppDescription;
  const appTagline = trimOrUndefined(chatMeta?.tagline);

  const features =
    chatMeta?.coreFeatures?.reduce<
      Array<{ title: string; description: string }>
    >((acc, feature) => {
      const title = trimOrUndefined(feature.title);
      const summary = trimOrUndefined(feature.summary);
      if (title && summary) {
        acc.push({ title, description: summary });
      }
      return acc;
    }, []) ?? [];

  const howItWorks =
    chatMeta?.highlightedQuestions?.reduce<
      Array<{ question: string; answer: string }>
    >((acc, item) => {
      const question = trimOrUndefined(item.question);
      const answer = trimOrUndefined(item.simulatedAnswer);
      if (question && answer) {
        acc.push({ question, answer });
      }
      return acc;
    }, []) ?? [];

  return {
    app: {
      name: appName,
      description: appDescription,
      tagline: appTagline,
    },
    features: features.length > 0 ? features : defaultFeatureCards,
    howItWorks:
      howItWorks.length > 0 ? howItWorks : defaultHowItWorksEntries,
  };
};

const normalizeResourceValue = (value: string): string =>
  value.endsWith("/") && value.length > 1 ? value.replace(/\/+$/, "") : value;

const appMatchesResource = (app: App, resource: string): boolean => {
  const target = normalizeResourceValue(resource);
  if (
    app.resource_uri &&
    normalizeResourceValue(app.resource_uri) === target
  ) {
    return true;
  }
  return app.mcp_server_ids.some(
    (serverId) => normalizeResourceValue(serverId) === target
  );
};

const selectDefaultApp = (apps: App[]): App | undefined => {
  const configuredAppId = CONFIG.defaultAppId?.trim();
  if (configuredAppId) {
    const matched = apps.find((app) => app.id === configuredAppId);
    if (matched) {
      return matched;
    }
  }
  const defaultServerId = CONFIG.defaultMcpServerId?.trim();
  if (defaultServerId) {
    const defaultApp = apps.find((app) =>
      appMatchesResource(app, defaultServerId)
    );
    if (defaultApp) {
      return defaultApp;
    }
  }

  const appsWithMcpIds = apps.filter((app) => app.mcp_server_ids.length > 0);
  if (appsWithMcpIds.length === 1) {
    return appsWithMcpIds[0];
  }

  if (appsWithMcpIds.length === 0) {
    const appsWithResource = apps.filter((app) =>
      Boolean(app.resource_uri.trim())
    );
    if (appsWithResource.length === 1) {
      return appsWithResource[0];
    }
    if (apps.length === 1) {
      return apps[0];
    }
  }

  return undefined;
};

const findAppByResourceLocal = async (
  resource: string
): Promise<App | undefined> => {
  const apps = await listApps();
  return apps.find((app) => appMatchesResource(app, resource));
};

const renderPage = (
  title: string,
  body: string,
  options?: RenderOptions
): string => `
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
      .panel { margin-top: 1.5rem; padding: 1.5rem; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 0.75rem; }
      .panel + .panel { margin-top: 1rem; }
      .badges { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.5rem 0 0; padding: 0; list-style: none; }
      .badge { display: inline-flex; align-items: center; padding: 0.25rem 0.75rem; background: #eef2ff; color: #1f2937; border-radius: 999px; font-size: 0.875rem; }
      .feedback { margin-top: 0.75rem; font-weight: 600; }
      .feedback.success { color: #2ecc71; }
      .feedback.error { color: #c0392b; }
      nav { margin-bottom: 1.5rem; }
      nav a { margin-right: 0.5rem; }
    </style>
  </head>
  <body>
    <nav>
      <a href="/">Home</a>
    </nav>
    ${body}
    ${options?.scripts ?? ""}
  </body>
</html>
`;

type RouteLogDetails = Record<string, unknown>;

const SENSITIVE_LOG_KEYS = new Set([
  "password",
  "password_hash",
  "clientsecret",
  "client_secret",
  "refresh_token",
  "access_token",
  "id_token",
  "idtoken",
  "registration_access_token",
  "registrationaccesstoken",
  "code",
  "token",
]);

const sanitizeForLogging = (input: unknown): unknown => {
  if (input === null || input === undefined) {
    return input;
  }
  if (input instanceof Date) {
    return input.toISOString();
  }
  if (Array.isArray(input)) {
    const limit = 20;
    const sanitized = input.slice(0, limit).map((item) => sanitizeForLogging(item));
    if (input.length > limit) {
      sanitized.push(`...${input.length - limit} more`);
    }
    return sanitized;
  }
  if (typeof input === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      const normalizedKey = key.toLowerCase();
      if (SENSITIVE_LOG_KEYS.has(normalizedKey)) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = sanitizeForLogging(value);
      }
    }
    return result;
  }
  if (typeof input === "string") {
    return input.length > 160 ? `${input.slice(0, 157)}...` : input;
  }
  return input;
};

const logHttpEvent = (
  method: string,
  url: string,
  phase: "request" | "response" | "error",
  details?: RouteLogDetails
) => {
  const prefix = `[${method} ${url}] ${phase}`;
  const sanitizedDetails = details ? sanitizeForLogging(details) : undefined;
  if (phase === "error") {
    if (sanitizedDetails) {
      console.error(prefix, sanitizedDetails);
    } else {
      console.error(prefix);
    }
  } else if (sanitizedDetails) {
    console.info(prefix, sanitizedDetails);
  } else {
    console.info(prefix);
  }
};

const buildRequestLogDetails = (req: express.Request): RouteLogDetails => {
  const details: RouteLogDetails = {};
  if (req.query && Object.keys(req.query).length > 0) {
    details.query = req.query;
  }
  if (req.body !== undefined) {
    const isEmptyObject =
      typeof req.body === "object" &&
      req.body !== null &&
      !Array.isArray(req.body) &&
      Object.keys(req.body as Record<string, unknown>).length === 0;
    const isEmptyString = typeof req.body === "string" && req.body.trim().length === 0;
    if (!isEmptyObject && !isEmptyString) {
      details.body = req.body;
    }
  }
  if (req.session?.userUuid) {
    details.sessionUser = req.session.userUuid;
  }
  return details;
};

const persistSession = async (req: express.Request): Promise<void> => {
  if (typeof req.session.save === "function") {
    await new Promise<void>((resolve, reject) => {
      req.session.save((err) => {
        if (err) {
          reject(err);
        } else {
          resolve();
        }
      });
    });
  }
};

const resolveSessionAppId = async (
  req: express.Request
): Promise<string | undefined> => {
  const authRequest = req.session?.authRequest as
    | PendingAuthRequest
    | undefined;
  if (!authRequest) {
    return undefined;
  }
  try {
    const appRecord = await findAppByResourceLocal(authRequest.resource);
    if (appRecord?.uuid) {
      return appRecord.uuid;
    }
  } catch (error) {
    console.warn("Failed to resolve app from resource", error);
  }
  try {
    const clientRecord = await findClientById(authRequest.client_id);
    if (clientRecord?.app_uuid) {
      return clientRecord.app_uuid;
    }
  } catch (error) {
    console.warn("Failed to resolve app from client", error);
  }
  return undefined;
};

type PaymentGateDecision =
  | { allowed: true }
  | { allowed: false; redirectPath: string }
  | { allowed: false; error: string };

type PaymentSessionApiResponse = {
  success?: boolean;
  data?: {
    sessionId?: string;
    url?: string;
    type?: string;
    paymentModel?: string;
    priceAmount?: number;
    [key: string]: unknown;
  };
  message?: string;
};

const formatPriceLabel = (model?: AppPaymentModel): string | undefined => {
  if (!model) {
    return undefined;
  }
  if (model.model === "subscription") {
    const price =
      typeof model.price === "number"
        ? `$${model.price.toFixed(2)}`
        : model.price !== undefined
        ? String(model.price)
        : undefined;
    const interval =
      typeof model.interval === "string" && model.interval.trim().length > 0
        ? model.interval.trim()
        : undefined;
    if (price && interval) {
      return `${price} / ${interval}`;
    }
    return price ?? undefined;
  }
  return undefined;
};

const createPaymentSession = async (
  userUuid: string,
  app: App
): Promise<{ url: string; sessionId?: string; raw?: Record<string, unknown> }> => {
  if (!CONFIG.paymentSessionApiUrl) {
    throw new Error("Payment session API URL is not configured.");
  }
  const response = await fetch(CONFIG.paymentSessionApiUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      app_userid: userUuid,
      app_id: app.id,
    }),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Payment session request failed (${response.status}): ${text || "no response body"}`
    );
  }
  let parsed: PaymentSessionApiResponse;
  try {
    parsed = (await response.json()) as PaymentSessionApiResponse;
  } catch (error) {
    throw new Error("Unable to parse payment session response.");
  }
  if (!parsed?.success || !parsed.data?.url) {
    throw new Error(
      parsed?.message ?? "Payment session API returned an unexpected payload."
    );
  }
  return {
    url: String(parsed.data.url),
    sessionId: parsed.data.sessionId
      ? String(parsed.data.sessionId)
      : undefined,
    raw:
      typeof parsed.data === "object" && parsed.data !== null
        ? (parsed.data as Record<string, unknown>)
        : undefined,
  };
};

const ensurePaymentAccess = async (
  req: express.Request,
  userUuid: string,
  authRequest: PendingAuthRequest
): Promise<PaymentGateDecision> => {
  let appRecord = await findAppByResourceLocal(authRequest.resource);
  if (!appRecord) {
    try {
      const client = await findClientById(authRequest.client_id);
      if (client) {
        appRecord = await findAppByUuid(client.app_uuid);
      }
    } catch (error) {
      console.warn("Failed to resolve app from client during payment check", error);
    }
  }

  if (!appRecord) {
    return { allowed: true };
  }

  const clearPending = async () => {
    if (req.session.pendingPayment) {
      req.session.pendingPayment = undefined;
      try {
        await persistSession(req);
      } catch (error) {
        console.warn(
          "Failed to persist session while clearing pending payment cache",
          error
        );
      }
    }
  };

  const paymentModel = appRecord.payment_model;
  const existingPending = req.session.pendingPayment;
  const hasPendingForUser =
    existingPending &&
    existingPending.appId === appRecord.id &&
    existingPending.userUuid === userUuid;

  if (!paymentModel || paymentModel.model === "free") {
    await clearPending();
    return { allowed: true };
  }

  if (paymentModel.model === "subscription") {
    try {
      const hasPayment = await userHasActivePayment(appRecord.id, userUuid);
      if (hasPayment) {
        await clearPending();
        return { allowed: true };
      }
    } catch (error) {
      console.error("Failed to verify payment status", error);
      return {
        allowed: false,
        error: "Unable to verify payment status. Please try again later.",
      };
    }

    if (hasPendingForUser && existingPending?.paymentLink) {
      return { allowed: false, redirectPath: "/auth/payment-required" };
    }

    try {
      const sessionInfo = await createPaymentSession(userUuid, appRecord);
      req.session.pendingPayment = {
        appId: appRecord.id,
        paymentLink: sessionInfo.url,
        appName: appRecord.name,
        startedAt: new Date().toISOString(),
        sessionId: sessionInfo.sessionId,
        userUuid,
        paymentModel,
      };
      await persistSession(req);
    } catch (error) {
      console.error("Failed to create payment session", error);
      return {
        allowed: false,
        error: "Unable to initiate payment session. Please try again later.",
      };
    }

    return { allowed: false, redirectPath: "/auth/payment-required" };
  }

  const paymentLink = appRecord.payment_link?.trim();
  if (!paymentLink) {
    await clearPending();
    return { allowed: true };
  }

  try {
    const hasPayment = await userHasActivePayment(appRecord.id, userUuid);
    if (hasPayment) {
      await clearPending();
      return { allowed: true };
    }
  } catch (error) {
    console.error("Failed to verify payment status", error);
    return {
      allowed: false,
      error: "Unable to verify payment status. Please try again later.",
    };
  }

  req.session.pendingPayment = {
    appId: appRecord.id,
    paymentLink,
    appName: appRecord.name,
    startedAt: new Date().toISOString(),
    userUuid,
    paymentModel,
  };
  try {
    await persistSession(req);
  } catch (error) {
    console.warn("Failed to persist session after setting pending payment", error);
  }

  return { allowed: false, redirectPath: "/auth/payment-required" };
};

const FIREBASE_VERSION = "12.4.0";
const FIREBASE_UI_VERSION = "6.0.2";

const buildFirebaseInitScript = (): string => {
  if (!CONFIG.firebaseClientConfig?.apiKey) {
    return "";
  }
  const firebaseConfig = JSON.stringify(CONFIG.firebaseClientConfig);
  return `
    <script src="https://www.gstatic.com/firebasejs/${FIREBASE_VERSION}/firebase-app-compat.js"></script>
    <script src="https://www.gstatic.com/firebasejs/${FIREBASE_VERSION}/firebase-auth-compat.js"></script>
    <script src="https://www.gstatic.com/firebasejs/${FIREBASE_VERSION}/firebase-analytics-compat.js"></script>
    <script>
      (function () {
        const firebaseConfig = ${firebaseConfig};
        window.__firebaseConfig = firebaseConfig;
        if (!window.firebase?.apps?.length) {
          firebase.initializeApp(firebaseConfig);
        }
        try {
          firebase.analytics();
        } catch (error) {
          console.warn("Firebase analytics unavailable", error);
        }
      })();
    </script>
  `;
};

type FirebaseUiMode = "login" | "register" | "auth";

const buildFirebaseUiSnippet = (mode: FirebaseUiMode = "auth"): string => {
  if (!CONFIG.firebaseClientConfig?.apiKey) {
    return "";
  }
  const modeLabel =
    mode === "register" ? "Sign up" : mode === "login" ? "Sign in" : "Sign in/up";
  return `
    ${buildFirebaseInitScript()}
    <link
      rel="stylesheet"
      href="https://www.gstatic.com/firebasejs/ui/${FIREBASE_UI_VERSION}/firebase-ui-auth.css"
    />
    <script src="https://www.gstatic.com/firebasejs/ui/${FIREBASE_UI_VERSION}/firebase-ui-auth.js"></script>
    <script>
      (function () {
        const firebaseConfig = window.__firebaseConfig;
        const authModeLabel = "${modeLabel}";
        const authState = window.__authState || {};
        const resumeAuth = authState?.resumeAuth || null;
        if (!firebaseConfig) {
          console.warn("Firebase config missing, cannot start FirebaseUI.");
          return;
        }
        if (!window.firebase?.apps?.length) {
          firebase.initializeApp(firebaseConfig);
        }
        const modal = document.getElementById("firebase-auth-modal");
        const closeButton = document.getElementById("close-firebase-modal");
        const backdrop = document.getElementById("firebase-auth-backdrop");
        const queryOpenButtons = () =>
          Array.from(
            document.querySelectorAll("[data-firebase-modal-trigger]")
          );
        let openButtons = queryOpenButtons();
        const statusEl = document.getElementById("firebaseui-status");
        const container = document.getElementById("firebaseui-modal-container");
        const headerAuthContainer = document.getElementById("header-auth-status");
        if (!modal || !container) {
          console.warn("Firebase modal container not found.");
          return;
        }

        const resetStatus = () => {
          if (!statusEl) return;
          statusEl.textContent = "";
          statusEl.className =
            "mt-4 text-sm font-medium text-slate-600 min-h-[1.75rem]";
        };

        const setStatus = (level, message) => {
          if (!statusEl) return;
          const base =
            "mt-4 text-sm font-medium min-h-[1.75rem] transition-colors";
          let color = "text-slate-600";
          if (level === "success") color = "text-emerald-600";
          if (level === "error") color = "text-rose-600";
          if (level === "loading") color = "text-indigo-600";
          statusEl.textContent = message;
          statusEl.className = base + " " + color;
        };

        const showModal = () => {
          modal.classList.remove("hidden");
          modal.classList.add("flex");
          resetStatus();
          startUi();
        };

        const hideModal = () => {
          modal.classList.add("hidden");
          modal.classList.remove("flex");
        };

        if (closeButton) {
          closeButton.addEventListener("click", (event) => {
            event.preventDefault();
            hideModal();
          });
        }
        if (backdrop) {
          backdrop.addEventListener("click", (event) => {
            event.preventDefault();
            hideModal();
          });
        }
        const bindOpenButtons = () => {
          openButtons.forEach((button) =>
            button.addEventListener("click", (event) => {
              event.preventDefault();
              showModal();
            })
          );
        };
        bindOpenButtons();

        const auth = firebase.auth();
        const ui =
          firebaseui.auth.AuthUI.getInstance() ??
          new firebaseui.auth.AuthUI(auth);
        let uiStarted = false;
        const providerConfig = ${JSON.stringify(CONFIG.firebaseUiProviders)};
        const signInOptions = (providerConfig || [])
          .map((provider) => {
            switch (provider) {
              case "google":
                return firebase.auth.GoogleAuthProvider.PROVIDER_ID;
              case "apple":
                return "apple.com";
              case "github":
                return {
                  provider: firebase.auth.GithubAuthProvider
                    ? firebase.auth.GithubAuthProvider.PROVIDER_ID
                    : "github.com",
                  scopes: ["user:email"],
                };
              case "microsoft":
                return {
                  provider: "microsoft.com",
                  scopes: ["email", "openid", "profile"],
                };
              case "twitter":
                return {
                  provider: firebase.auth.TwitterAuthProvider
                    ? firebase.auth.TwitterAuthProvider.PROVIDER_ID
                    : "twitter.com",
                  customParameters: { include_email: "true" },
                };
              case "facebook":
                return {
                  provider: firebase.auth.FacebookAuthProvider
                    ? firebase.auth.FacebookAuthProvider.PROVIDER_ID
                    : "facebook.com",
                  scopes: ["email"],
                };
              case "email":
              default:
                return firebase.auth.EmailAuthProvider.PROVIDER_ID;
            }
          })
          .filter(Boolean);
        if (!signInOptions.length) {
          signInOptions.push(firebase.auth.EmailAuthProvider.PROVIDER_ID);
        }

        const renderHeaderAuthEmail = (email) => {
          if (!headerAuthContainer || !email) {
            return;
          }
          const safeEmail = String(email).trim();
          headerAuthContainer.innerHTML = "";
          const wrapper = document.createElement("span");
          wrapper.className = "text-sm text-gray-600";
          const label = document.createElement("span");
          label.textContent = "Logged in: ";
          const value = document.createElement("span");
          value.className = "font-semibold text-gray-900";
          value.textContent = safeEmail;
          wrapper.appendChild(label);
          wrapper.appendChild(value);
          headerAuthContainer.appendChild(wrapper);
          openButtons = queryOpenButtons();
        };

        const processAuthResult = async (authResult) => {
          const email =
            authResult?.user?.email || authResult?.user?.uid || "";
          setStatus("loading", "Firebase " + authModeLabel + " successful: " + email + ", verifying...");
          try {
            const idToken = await authResult.user.getIdToken();
            const requestPayload = { idToken };
            if (resumeAuth) {
              requestPayload.resume = resumeAuth;
            }
            const response = await fetch("/auth/firebase/session", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify(requestPayload),
              credentials: "same-origin",
            });
            const payload = await response.json().catch(() => ({}));
            if (!response.ok || !payload?.ok) {
              const message =
                payload?.error ||
                payload?.message ||
                "Server failed to complete login verification.";
              throw new Error(message);
            }
            setStatus("success", "Login successful, redirecting...");
            renderHeaderAuthEmail(email);
            if (payload.redirect) {
              window.location.assign(payload.redirect);
            } else if (authState?.pendingAuth) {
              window.location.assign("/oauth/authorize");
            } else {
              setTimeout(() => hideModal(), 800);
            }
          } catch (err) {
            console.error("Firebase login verification failed", err);
            setStatus(
              "error",
              "Firebase login verification failed: " + (err?.message || "Unknown error")
            );
          }
        };

        const uiConfig = {
          signInFlow: "popup",
          signInOptions,
          tosUrl: "${CONFIG.docsUrl}",
          privacyPolicyUrl: "${CONFIG.privacyPolicyUrl}",
          callbacks: {
            signInSuccessWithAuthResult: function (authResult) {
              processAuthResult(authResult);
              return false;
            },
            signInFailure: function (error) {
              console.error("Firebase UI sign-in failure", error);
              setStatus(
                "error",
                "Firebase " +
                  authModeLabel +
                  " failed: " +
                  (error?.message ?? "Unknown error")
              );
              return Promise.resolve();
            },
          },
        };

        const startUi = () => {
          if (uiStarted) {
            return;
          }
          ui.start("#firebaseui-modal-container", uiConfig);
          uiStarted = true;
        };

        const shouldAutoOpen =
          (!!authState && authState.autoOpenFirebase && !authState.currentUserEmail) ||
          false;
        if (shouldAutoOpen) {
          showModal();
        }

        window.__openFirebaseModal = showModal;
      })();
    </script>
  `;
};

type AppOverviewOptions = {
  clientId?: string;
  mcpUrl?: string;
  app?: App;
  client?: Client;
  error?: string;
  pendingAuth?: {
    clientName: string;
    redirectUri: string;
    scopes: string[];
  };
  autoOpenFirebase?: boolean;
  currentUserEmail?: string;
  authResume?: AuthResumePayload;
};

type FirebaseAccountRecord = {
  uid: string;
  email: string;
  displayName?: string;
};

const decodeJwtPayload = (token: string): Record<string, unknown> | undefined => {
  const [, payload] = token.split(".");
  if (!payload) {
    return undefined;
  }
  try {
    const decoded = Buffer.from(payload, "base64url").toString("utf8");
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch (error) {
    console.warn("Failed to decode Firebase ID token payload", error);
    return undefined;
  }
};

const verifyFirebaseIdToken = async (
  idToken: string
): Promise<FirebaseAccountRecord> => {
  if (!CONFIG.firebaseClientConfig?.apiKey) {
    throw new Error("Firebase API Key not configured, cannot verify login.");
  }
  const apiKey = CONFIG.firebaseClientConfig.apiKey;
  const payload = JSON.stringify({ idToken });
  const endpoint = new URL(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`
  );

  const responseBody: string = await new Promise((resolve, reject) => {
    const request = https.request(
      {
        method: "POST",
        hostname: endpoint.hostname,
        path: endpoint.pathname + endpoint.search,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve(data);
          } else {
            reject(
              new Error(
                `Firebase verification failed (status ${res.statusCode ?? "unknown"}): ${
                  data || "No response content"
                }`
              )
            );
          }
        });
      }
    );
    request.on("error", (error) => reject(error));
    request.write(payload);
    request.end();
  });

  type FirebaseLookupResponse = {
    users?: Array<{
      localId?: string;
      email?: string;
      displayName?: string;
      providerUserInfo?: Array<{
        email?: string;
        displayName?: string;
        providerId?: string;
        rawId?: string;
      }>;
    }>;
  };

  let parsed: FirebaseLookupResponse;
  try {
    parsed = JSON.parse(responseBody) as FirebaseLookupResponse;
  } catch {
    throw new Error("Cannot parse Firebase return data.");
  }

  const tokenPayload = decodeJwtPayload(idToken);
  const user = parsed.users?.[0];
  const providerDisplayName =
    user?.providerUserInfo?.find(
      (info) =>
        typeof info?.displayName === "string" && info.displayName.trim().length > 0
    )?.displayName ?? undefined;
  const providerEmail =
    user?.providerUserInfo?.find(
      (info) => typeof info?.email === "string" && info.email.trim().length > 0
    )?.email ?? undefined;
  const payloadEmail =
    typeof tokenPayload?.email === "string" && tokenPayload.email.trim().length > 0
      ? tokenPayload.email
      : undefined;

  const email = (user?.email ?? providerEmail ?? payloadEmail)?.trim();
  if (!email) {
    throw new Error("Firebase account missing email information.");
  }

  const payloadName =
    typeof tokenPayload?.name === "string" && tokenPayload.name.trim().length > 0
      ? tokenPayload.name
      : undefined;
  const displayName =
    (typeof user?.displayName === "string" && user.displayName.trim().length > 0
      ? user.displayName
      : undefined) ??
    providerDisplayName ??
    payloadName;
  const uid =
    (typeof user?.localId === "string" && user.localId.trim().length > 0
      ? user.localId
      : undefined) ??
    (typeof tokenPayload?.user_id === "string" && tokenPayload.user_id.trim().length > 0
      ? tokenPayload.user_id
      : undefined) ??
    (typeof tokenPayload?.sub === "string" && tokenPayload.sub.trim().length > 0
      ? tokenPayload.sub
      : "");

  return {
    uid,
    email,
    displayName,
  };
};

const completeAuthorizationRequest = async (
  req: express.Request,
  userUuid: string,
  authRequest: PendingAuthRequest
): Promise<string> => {
  const code = crypto.randomBytes(32).toString("base64url");
  const expiresAt = Math.floor(Date.now() / 1000) + 600;
  await persistAuthorizationCode({
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
  await persistSession(req);
  return redirect.toString();
};

const createLucideSvg = (paths: string, className?: string): string => {
  const svgClass = className && className.trim().length > 0 ? className : "w-6 h-6";
  return `
    <svg xmlns="http://www.w3.org/2000/svg" class="${svgClass}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
      ${paths}
    </svg>
  `;
};

const iconSparkles = (className?: string): string =>
  createLucideSvg(
    `
      <path d="M9.937 15.5A2 2 0 0 0 8.5 14.063l-6.135-1.582a.5.5 0 0 1 0-.962L8.5 9.936A2 2 0 0 0 9.937 8.5l1.582-6.135a.5.5 0 0 1 .963 0L14.063 8.5A2 2 0 0 0 15.5 9.937l6.135 1.581a.5.5 0 0 1 0 .964L15.5 14.063a2 2 0 0 0-1.437 1.437l-1.582 6.135a.5.5 0 0 1-.963 0z" />
      <path d="M20 3v4" />
      <path d="M22 5h-4" />
      <path d="M4 17v2" />
      <path d="M5 18H3" />
    `,
    className
  );

const iconZap = (className?: string): string =>
  createLucideSvg(
    `
      <path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z" />
    `,
    className
  );

const iconShield = (className?: string): string =>
  createLucideSvg(
    `
      <path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" />
    `,
    className
  );

const iconTrendingUp = (className?: string): string =>
  createLucideSvg(
    `
      <path d="M16 7h6v6" />
      <path d="m22 7-8.5 8.5-5-5L2 17" />
    `,
    className
  );

const iconMessageCircle = (className?: string): string =>
  createLucideSvg(
    `
      <path d="M7.9 20A9 9 0 1 0 4 16.1L2 22Z" />
    `,
    className
  );

const iconBot = (className?: string): string =>
  createLucideSvg(
    `
      <path d="M12 8V4H8" />
      <rect width="16" height="12" x="4" y="8" rx="2" />
      <path d="M2 14h2" />
      <path d="M20 14h2" />
      <path d="M15 13v2" />
      <path d="M9 13v2" />
    `,
    className
  );

const iconArrowRight = (className?: string): string =>
  createLucideSvg(
    `
      <path d="M5 12h14" />
      <path d="m12 5 7 7-7 7" />
    `,
    className
  );

const iconCheck = (className?: string): string =>
  createLucideSvg(
    `
      <path d="M20 6 9 17l-5-5" />
    `,
    className
  );

const iconCrown = (className?: string): string =>
  createLucideSvg(
    `
      <path d="M11.562 3.266a.5.5 0 0 1 .876 0L15.39 8.87a1 1 0 0 0 1.516.294L21.183 5.5a.5.5 0 0 1 .798.519l-2.834 10.246a1 1 0 0 1-.956.734H5.81a1 1 0 0 1-.957-.734L2.02 6.02a.5.5 0 0 1 .798-.519l4.276 3.664a1 1 0 0 0 1.516-.294z" />
      <path d="M5 21h14" />
    `,
    className
  );

const iconX = (className?: string): string =>
  createLucideSvg(
    `
      <path d="M18 6 6 18" />
      <path d="m6 6 12 12" />
    `,
    className
  );

const renderLandingPage = (options: AppOverviewOptions): string => {
  const {
    clientId,
    mcpUrl,
    app,
    client,
    error,
    pendingAuth,
    autoOpenFirebase,
    currentUserEmail,
  } = options;
  const hasFirebase = Boolean(CONFIG.firebaseClientConfig?.apiKey);
  const shouldAutoOpenFirebase =
    hasFirebase && !currentUserEmail && Boolean(autoOpenFirebase);
  const docsUrl =
    CONFIG.docsUrl && CONFIG.docsUrl.trim().length > 0
      ? CONFIG.docsUrl
      : "https://chatgpt.com/";
  const contactLink =
    CONFIG.adminContact && CONFIG.adminContact.trim().length > 0
      ? CONFIG.adminContact
      : "mailto:admin@example.com";
  const contactLabel = contactLink.startsWith("mailto:")
    ? contactLink.replace(/^mailto:/, "")
    : contactLink.replace(/^https?:\/\//, "");
  const landingPageContent = deriveLandingPageContent(options.app?.meta_info);
  const appName =
    landingPageContent.app.name && landingPageContent.app.name.trim().length > 0
      ? landingPageContent.app.name.trim()
      : "Smart App Name";
  const heroTitle = appName;
  const heroTagline =
    landingPageContent.app.tagline &&
    landingPageContent.app.tagline.trim().length > 0
      ? landingPageContent.app.tagline.trim()
      : undefined;
  const appInitial = appName.charAt(0).toUpperCase() || "S";

  const defaultFeatureIcons: Array<(className?: string) => string> = [
    iconSparkles,
    iconZap,
    iconShield,
    iconTrendingUp,
  ];

  const featuresHtml = landingPageContent.features
    .map((feature, index) => {
      const iconRenderer =
        defaultFeatureIcons[index % defaultFeatureIcons.length];
      return `
        <article class="glow-card" data-animate="fade-up" style="--delay:${index * 80}ms" data-tilt>
          <div class="icon-wrapper">
            ${iconRenderer("w-6 h-6")}
          </div>
          <h3 class="text-xl font-semibold text-slate-900 mb-3">${escapeHtml(feature.title)}</h3>
          <p class="text-slate-600 leading-relaxed text-sm md:text-base">${escapeHtml(feature.description)}</p>
        </article>
      `;
    })
    .join("");

  const conversationEntries = landingPageContent.howItWorks.flatMap((item) => {
    const question = trimOrUndefined(item.question);
    const answer = trimOrUndefined(item.answer);
    const entries: Array<{ type: "user" | "assistant"; message: string }> = [];
    if (question) {
      entries.push({ type: "user", message: question });
    }
    if (answer) {
      entries.push({ type: "assistant", message: answer });
    }
    return entries;
  });

  const howItWorksHtml = conversationEntries
    .map((entry, index) => {
      const isUser = entry.type === "user";
      const alignmentClass = isUser ? "justify-end" : "justify-start";
      const rowDirection = isUser ? "flex-row-reverse" : "";
      const bubbleClass = isUser
        ? "chat-bubble user"
        : "chat-bubble assistant";
      const iconWrapperClass = isUser
        ? "chat-avatar user"
        : "chat-avatar assistant";
      const icon = isUser
        ? iconMessageCircle("w-5 h-5 text-white")
        : iconBot("w-5 h-5 text-white");
      return `
        <div class="chat-row ${alignmentClass}" data-animate="fade-up" style="--delay:${index * 80}ms">
          <div class="chat-entry ${rowDirection}">
            <div class="${iconWrapperClass}">
              ${icon}
            </div>
            <div class="${bubbleClass}">
              <p class="chat-text">${escapeHtml(entry.message)}</p>
            </div>
          </div>
        </div>
      `;
    })
    .join("");

  const pendingAuthSummary = pendingAuth
    ? `
      <div class="pending-card" data-animate="fade-up">
        <span class="pending-badge">
          ${iconSparkles("w-4 h-4")}
          Pending authorization
        </span>
        <p class="mt-3 text-sm md:text-base text-indigo-900 leading-relaxed">
          The client <span class="font-semibold">${escapeHtml(
            pendingAuth.clientName
          )}</span> will be authorized with the following permissions before redirecting to
          <code>${escapeHtml(pendingAuth.redirectUri)}</code>.
        </p>
        <div class="flex flex-wrap gap-2 mt-4">
          ${pendingAuth.scopes
            .map(
              (scope, scopeIndex) =>
                `<span class="badge-soft" style="--delay:${scopeIndex * 40}ms">${escapeHtml(
                  scope
                )}</span>`
            )
            .join("")}
        </div>
      </div>
    `
    : "";

  let clientDetails = `
    <div class="info-panel" data-animate="fade-up">
      <h3 class="text-2xl font-semibold text-slate-900 mb-3">Application information</h3>
      <p class="text-slate-600 leading-relaxed">
        Use the query panel on the right to input <code>client_id</code> or provide the <code>mcpUrl</code> of your MCP server to view the resources and permissions bound to the client.
      </p>
    </div>
  `;

  if (clientId && !app && !client && !error) {
    clientDetails = `
      <div class="info-panel border border-rose-200/70" data-animate="fade-up">
        <h3 class="text-2xl font-semibold text-rose-600 mb-3">Client not found</h3>
        <p class="text-rose-500 text-base leading-relaxed">
          No client record found for client_id <code>${escapeHtml(
            clientId
          )}</code>.
        </p>
      </div>
    `;
  }

  if (error) {
    clientDetails = `
      <div class="info-panel border border-rose-200/70" data-animate="fade-up">
        <h3 class="text-2xl font-semibold text-rose-600 mb-3">Load failed</h3>
        <p class="text-rose-500 text-base leading-relaxed">${escapeHtml(error)}</p>
      </div>
    `;
  }

  if (app && client) {
    const scopes = getAppScopes(app);
    const scopesList = scopes.length
      ? scopes
          .map(
            (scope, scopeIndex) =>
              `<span class="badge-soft" style="--delay:${scopeIndex * 40}ms">${escapeHtml(
                scope
              )}</span>`
          )
          .join("")
      : '<span class="text-sm text-slate-500">The application has not configured default scopes.</span>';
    const redirectList = client.redirect_uris.length
      ? client.redirect_uris
          .map(
            (uri) =>
              `<li class="text-sm text-slate-600 break-all"><code>${escapeHtml(
                uri
              )}</code></li>`
          )
          .join("")
      : '<li class="text-sm text-slate-500">The client has not configured redirect URIs.</li>';
    clientDetails = `
      <div class="info-panel space-y-5" data-animate="fade-up">
        <div class="flex flex-col gap-2">
          <h3 class="text-2xl font-semibold text-slate-900">${escapeHtml(app.name)}</h3>
          ${
            client.client_name
              ? `<p class="text-slate-500 text-sm">Client name: <span class="font-medium text-slate-800">${escapeHtml(
                  client.client_name
                )}</span></p>`
              : ""
          }
        </div>
        <div class="grid md:grid-cols-2 gap-4">
          <div class="p-4 rounded-xl border border-slate-200/60 bg-white/60">
            <p class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Client ID</p>
            <p class="mt-2 font-mono text-sm break-all text-slate-800">${escapeHtml(
              client.client_id
            )}</p>
          </div>
          <div class="p-4 rounded-xl border border-slate-200/60 bg-white/60">
            <p class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">Resource URI</p>
            <p class="mt-2 font-mono text-sm break-all text-slate-800">${escapeHtml(
              app.resource_uri
            )}</p>
          </div>
        </div>
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400 mb-2">Default scopes</p>
          <div class="flex flex-wrap gap-2">${scopesList}</div>
        </div>
        <div>
          <p class="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400 mb-2">Redirect URIs</p>
          <ul class="space-y-1">${redirectList}</ul>
        </div>
      </div>
    `;
  }

  const clientDetailsBlock = pendingAuthSummary + clientDetails;

  const firebaseModal = hasFirebase
    ? `
      <div
        id="firebase-auth-modal"
        class="fixed inset-0 z-50 hidden items-center justify-center px-4"
        aria-hidden="true"
      >
        <div
          id="firebase-auth-backdrop"
          class="absolute inset-0 bg-slate-900/70 backdrop-blur-sm"
        ></div>
        <div class="relative w-full max-w-lg mx-auto">
          <div class="bg-white rounded-2xl shadow-2xl overflow-hidden">
            <div class="flex items-center justify-between px-6 py-4 border-b border-slate-200">
              <div>
                <p class="text-sm font-semibold text-indigo-600">${escapeHtml(appName)}</p>
                <h3 class="text-lg font-bold text-gray-900 mt-1">Use ${escapeHtml(appName)} Sign In</h3>
              </div>
              <button
                id="close-firebase-modal"
                class="p-2 text-gray-500 hover:text-gray-900 transition-colors"
                aria-label="Close login window"
              >
                <svg xmlns="http://www.w3.org/2000/svg" class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M6 18 18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div class="px-6 py-6">
              <div id="firebaseui-modal-container"></div>
              <p id="firebaseui-status" class="mt-4 text-sm font-medium text-slate-600 min-h-[1.75rem]"></p>
            </div>
          </div>
        </div>
      </div>
    `
    : "";

  const heroSection = `
    <section class="hero-section relative overflow-hidden min-h-screen flex items-center justify-center py-24 md:py-28">
      <div class="absolute inset-0 overflow-hidden">
        <div aria-hidden="true" class="hero-aurora"></div>
      </div>
      <div class="hero-decoration" aria-hidden="true">
        <span></span>
        <span></span>
        <span></span>
      </div>
      <div class="relative w-full">
        <div class="hero-copy max-w-5xl mx-auto px-6 text-center flex flex-col items-center gap-6">
          <div class="inline-flex items-center gap-2 px-3 py-1.5 rounded-full floating-badge" data-animate="fade-up">
            <h1 class="text-4xl md:text-6xl font-bold leading-tight text-slate-900 word-fade" data-animate-words>
            ${escapeHtml(heroTitle)}
          </h1>
          </div>
          
          ${
            heroTagline
              ? `<p class="max-w-2xl mx-auto text-lg md:text-2xl text-slate-700 word-fade" data-animate-words style="--delay: 80ms">
              ${escapeHtml(heroTagline)}
            </p>`
              : ""
          }
          <p class="hero-description max-w-3xl mx-auto text-base md:text-lg text-slate-600 leading-relaxed" data-typewriter>
            ${escapeHtml(landingPageContent.app.description)}
          </p>
          <div class="flex flex-col sm:flex-row items-center justify-center gap-3" data-animate="fade-up" style="--delay: 160ms">
            <a href="${escapeHtml(
              docsUrl
            )}" target="_blank" rel="noopener noreferrer" class="inline-flex items-center gap-2 rounded-full px-7 py-3 bg-slate-900 text-white font-semibold shadow-lg shadow-indigo-200/40 hover:bg-black transition">
              <span>Use Now in ChatGPT</span>
              ${iconArrowRight("w-5 h-5")}
            </a>
            ${
              hasFirebase
                ? `<button type="button" data-open-firebase class="inline-flex items-center gap-2 rounded-full px-7 py-3 border border-slate-300/70 bg-white/80 text-slate-800 font-semibold shadow-sm hover:border-slate-400 transition">
                  <span>Sign in to Continue</span>
                </button>`
                : ""
            }
          </div>
        </div>
      </div>
    </section>
  `;

  const featureSection = `
    <section id="features" class="py-20 bg-transparent">
      <div class="max-w-6xl mx-auto px-6">
        <h2 class="section-title" data-animate="fade-up">Core Capabilities</h2>
        <p class="section-subtitle" data-animate="fade-up" style="--delay: 60ms">
          Powerful features providing you with an exceptional experience
        </p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
          ${featuresHtml}
        </div>
      </div>
    </section>
  `;

  const howItWorksSection = `
    <section id="how-it-works" class="py-20 bg-slate-50/60">
      <div class="max-w-4xl mx-auto px-6">
        <h2 class="section-title" data-animate="fade-up">How It Works</h2>
        <div class="chat-thread">
          ${howItWorksHtml}
        </div>
      </div>
    </section>
  `;

  const clientOverviewSection = `
    <section id="overview" class="py-20 bg-transparent">
      <div class="max-w-6xl mx-auto px-6">
        <div class="grid lg:grid-cols-[1.1fr,0.9fr] gap-10">
          <div class="space-y-6">
            ${clientDetailsBlock}
          </div>
          <div class="glass-panel" data-animate="fade-up" style="--delay: 140ms">
            <h3 class="text-2xl font-semibold mb-4">Query client</h3>
            <p class="text-slate-200/80 text-sm leading-relaxed mb-6">
              Provide a <span class="font-semibold">client_id</span> or the <span class="font-semibold">mcpUrl</span> associated with your MCP server to load the registration information and default scopes of the client.
            </p>
            <form method="get" action="/" class="space-y-4">
              <label class="block text-xs font-semibold uppercase tracking-[0.22em] text-slate-300">
                Client ID
                <input
                  type="text"
                  name="client_id"
                  value="${clientId ? escapeHtml(clientId) : ""}"
                  placeholder="Input client_id"
                  class="mt-2 block w-full rounded-xl px-4 py-3 bg-transparent border focus:outline-none focus:ring-2 focus:ring-indigo-200/70"
                />
              </label>
              <label class="block text-xs font-semibold uppercase tracking-[0.22em] text-slate-300">
                MCP URL
                <input
                  type="text"
                  name="mcpUrl"
                  value="${mcpUrl ? escapeHtml(mcpUrl) : ""}"
                  placeholder="Input MCP server URL"
                  class="mt-2 block w-full rounded-xl px-4 py-3 bg-transparent border focus:outline-none focus:ring-2 focus:ring-indigo-200/70"
                />
              </label>
              <button
                type="submit"
                class="w-full inline-flex items-center justify-center gap-2 px-5 py-3 rounded-xl bg-white text-slate-900 font-semibold hover:bg-slate-100 transition"
              >
                View client details
              </button>
            </form>
            <p class="mt-6 text-xs text-slate-300/80 leading-relaxed">
              Tip: The <code>?client_id=</code> or <code>&amp;mcpUrl=</code> parameters in the OAuth callback can jump directly to the query results of this page.
            </p>
          </div>
        </div>
      </div>
    </section>
  `;

  const footerSection = `
    <footer class="bg-slate-950 text-white py-12 mt-24">
      <div class="max-w-6xl mx-auto px-6 text-center space-y-3">
        <p class="text-sm text-slate-300">
          © ${new Date().getFullYear()} ${escapeHtml(appName)}. All rights reserved.
        </p>
        <!--<p class="text-xs text-slate-500">
          Need support? <a href="${escapeHtml(
            contactLink
          )}" class="text-indigo-300 font-medium hover:text-indigo-200 transition">${escapeHtml(
    contactLabel
  )}</a>
        </p>-->
      </div>
    </footer>
  `;

  const authStateScript = hasFirebase
    ? `<script>window.__authState = ${serializeForScript({
        pendingAuth: pendingAuth
          ? {
              clientName: pendingAuth.clientName,
              redirectUri: pendingAuth.redirectUri,
              scopes: pendingAuth.scopes,
            }
          : null,
        autoOpenFirebase: shouldAutoOpenFirebase,
        currentUserEmail: currentUserEmail ?? null,
        resumeAuth: options.authResume ?? null,
      })};</script>`
    : "";

  const firebaseSnippet = hasFirebase ? buildFirebaseUiSnippet("auth") : "";

  const headerAction = currentUserEmail
    ? `<span class="text-sm font-medium text-slate-600 bg-white/70 rounded-full px-4 py-1.5 border border-slate-200 shadow-sm">Logged in: <span class="font-semibold text-slate-900">${escapeHtml(
        currentUserEmail
      )}</span></span>`
    : hasFirebase
    ? `<button type="button" data-open-firebase class="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-slate-200 bg-white/70 text-slate-700 font-semibold shadow-sm hover:border-slate-300 transition">
        <span>Sign in</span>
      </button>`
    : `<a href="${escapeHtml(
        docsUrl
      )}" class="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-slate-200 bg-white/70 text-slate-700 font-semibold shadow-sm hover:border-slate-300 transition">
        Documentation
      </a>`;

  const animationScript = `
    <script>
      (function () {
        const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        const wordElements = Array.from(document.querySelectorAll("[data-animate-words]"));

        const showWordElement = (element) => {
          element.classList.add("is-visible");
        };

        const typewriterElements = Array.from(document.querySelectorAll("[data-typewriter]"));
        typewriterElements.forEach((element) => {
          const text = (element.textContent || "").trim();
          element.setAttribute("data-typewriter-text", text);
          element.textContent = "";
        });

        const playTypewriter = (element) => {
          if (element.classList.contains("is-complete")) {
            return;
          }
          const text = element.getAttribute("data-typewriter-text") || "";
          let index = 0;
          const tick = () => {
            element.textContent = text.slice(0, index);
            index += 1;
            if (index <= text.length) {
              setTimeout(tick, 18);
            } else {
              element.classList.add("is-complete");
              element.textContent = text;
            }
          };
          tick();
        };

        const animatedElements = Array.from(document.querySelectorAll("[data-animate]"));

        if (prefersReduced) {
          animatedElements.forEach((el) => el.classList.add("is-visible"));
          wordElements.forEach(showWordElement);
          typewriterElements.forEach((element) => {
            element.textContent = element.getAttribute("data-typewriter-text") || "";
            element.classList.add("is-complete");
          });
          return;
        }

        const observer = new IntersectionObserver(
          (entries, obs) => {
            entries.forEach((entry) => {
              if (!entry.isIntersecting) {
                return;
              }
              const target = entry.target;
              const explicitDelay = target.getAttribute("data-delay");
              const styleDelay = target.style.getPropertyValue("--delay");
              const delay = explicitDelay ? parseInt(explicitDelay, 10) : parseInt(styleDelay || "0", 10);
              if (delay) {
                setTimeout(() => target.classList.add("is-visible"), delay);
              } else {
                target.classList.add("is-visible");
              }
              obs.unobserve(target);
            });
          }
        );

        animatedElements.forEach((element) => observer.observe(element));

        const wordObserver = new IntersectionObserver(
          (entries, obs) => {
            entries.forEach((entry) => {
              if (!entry.isIntersecting) {
                return;
              }
              showWordElement(entry.target);
              obs.unobserve(entry.target);
            });
          },
          { threshold: 0.35, rootMargin: "0px 0px -10% 0px" }
        );

        wordElements.forEach((element) => wordObserver.observe(element));

        typewriterElements.forEach((element) => {
          const typeObserver = new IntersectionObserver(
            (entries, typeObs) => {
              entries.forEach((entry) => {
                if (!entry.isIntersecting) {
                  return;
                }
                playTypewriter(element);
                typeObs.unobserve(entry.target);
              });
            },
            { threshold: 0.35 }
          );
          typeObserver.observe(element);
        });

        const tiltTargets = Array.from(document.querySelectorAll("[data-tilt]"));
        if (tiltTargets.length) {
          let rafId = 0;
          const resetTilt = (element) => {
            element.style.setProperty("--tilt-x", "0deg");
            element.style.setProperty("--tilt-y", "0deg");
          };
          document.addEventListener("pointermove", (event) => {
            if (rafId) {
              cancelAnimationFrame(rafId);
            }
            rafId = requestAnimationFrame(() => {
              tiltTargets.forEach((card) => {
                const rect = card.getBoundingClientRect();
                if (!rect.width || !rect.height) {
                  return;
                }
                const relativeX = (event.clientX - rect.left) / rect.width - 0.5;
                const relativeY = (event.clientY - rect.top) / rect.height - 0.5;
                const rotateX = (relativeY * -8).toFixed(2);
                const rotateY = (relativeX * 8).toFixed(2);
                card.style.setProperty("--tilt-x", rotateX + "deg");
                card.style.setProperty("--tilt-y", rotateY + "deg");
              });
            });
          });
          document.addEventListener("pointerleave", () => {
            tiltTargets.forEach(resetTilt);
          });
          tiltTargets.forEach((card) => {
            card.addEventListener("mouseleave", () => resetTilt(card));
          });
        }

        document.querySelectorAll("[data-open-firebase]").forEach((button) => {
          button.addEventListener("click", () => {
            if (typeof window.__openFirebaseModal === "function") {
              window.__openFirebaseModal();
            }
          });
        });
      })();
    </script>
  `;

  return `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(heroTitle)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet" />
    <script>
      (function () {
        const NativeMutationObserver = window.MutationObserver;
        if (!NativeMutationObserver) {
          return;
        }
        const originalObserve = NativeMutationObserver.prototype.observe;
        NativeMutationObserver.prototype.observe = function (target, options) {
          if (!(target instanceof Node)) {
            console.warn("Skipped observing non-Node target", target);
            return;
          }
          return originalObserve.call(this, target, options);
        };
      })();
    </script>
    <script src="https://cdn.tailwindcss.com?plugins=forms,typography"></script>
    <script>
      tailwind.config = {
        theme: {
          extend: {
            fontFamily: {
              sans: ["Inter", "system-ui", "-apple-system", "BlinkMacSystemFont", '"Segoe UI"', "sans-serif"],
            },
          },
        },
      };
    </script>
    <style>
      :root {
        --white: #ffffff;
        --black: #0f172a;
        --transparent: rgba(255, 255, 255, 0);
        --blue-500: #3b82f6;
        --blue-400: #60a5fa;
        --blue-300: #93c5fd;
        --indigo-300: #a5b4fc;
        --violet-200: #ddd6fe;
      }
      body { font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: linear-gradient(180deg, #f8fafc 0%, #eef2ff 100%); color: #0f172a; }
      ::selection { background: rgba(79, 70, 229, 0.2); }
      main { overflow: hidden; }
      [data-animate] { opacity: 0; transform: translateY(24px) scale(0.98); transition: opacity 0.6s ease, transform 0.6s ease; }
      [data-animate].is-visible { opacity: 1; transform: none; }
      .word-fade { opacity: 0; display: inline-block; transform: translateY(12px); transition: opacity 0.45s ease, transform 0.45s ease; }
      .word-fade.is-visible { opacity: 1; transform: translateY(0); }
      [data-typewriter] { position: relative; min-height: 1.6em; }
      [data-typewriter]::after { content: ""; position: absolute; width: 2px; height: 1.1em; background: currentColor; right: -6px; top: 50%; transform: translateY(-50%); animation: blink 1s steps(1) infinite; }
      [data-typewriter].is-complete::after { display: none; }
      .hero-section { position: relative; isolation: isolate; }
      .hero-decoration { position: absolute; inset: 0; overflow: hidden; pointer-events: none; z-index: 1; }
      .hero-decoration span { position: absolute; border-radius: 999px; filter: blur(90px); opacity: 0.65; }
      .hero-decoration span:nth-child(1) { background: rgba(129, 140, 248, 0.6); width: 420px; height: 420px; top: -160px; right: -100px; animation: gradientShift 18s ease-in-out infinite; }
      .hero-decoration span:nth-child(2) { background: rgba(56, 189, 248, 0.5); width: 380px; height: 380px; bottom: -140px; left: -80px; animation: gradientShift 20s ease-in-out infinite reverse; }
      .hero-decoration span:nth-child(3) { background: rgba(59, 130, 246, 0.45); width: 320px; height: 320px; top: 30%; left: 50%; transform: translate(-50%, -50%); animation: gradientShift 22s ease-in-out infinite; }
      .hero-aurora { position: absolute; inset: -10px; z-index: 0; pointer-events: none; filter: blur(10px); opacity: 0.55; will-change: transform; --white-gradient: repeating-linear-gradient(100deg, rgba(255, 255, 255, 1) 0%, rgba(255, 255, 255, 1) 7%, rgba(255, 255, 255, 0) 10%, rgba(255, 255, 255, 0) 12%, rgba(255, 255, 255, 1) 16%); --dark-gradient: repeating-linear-gradient(100deg, rgba(15, 23, 42, 1) 0%, rgba(15, 23, 42, 1) 7%, rgba(15, 23, 42, 0) 10%, rgba(15, 23, 42, 0) 12%, rgba(15, 23, 42, 1) 16%); --aurora: repeating-linear-gradient(100deg, rgba(59, 130, 246, 1) 10%, rgba(165, 180, 252, 1) 15%, rgba(147, 197, 253, 1) 20%, rgba(221, 214, 254, 1) 25%, rgba(96, 165, 250, 1) 30%); background-image: var(--white-gradient), var(--aurora); background-size: 300%, 200%; background-position: 50% 50%, 50% 50%; mask-image: radial-gradient(ellipse at 100% 0%, rgba(0, 0, 0, 1) 10%, rgba(0, 0, 0, 0) 70%); animation: aurora 26s ease-in-out infinite; mix-blend-mode: screen; }
      .hero-aurora::after { content: ""; position: absolute; inset: 0; background-image: var(--white-gradient), var(--aurora); background-size: 200%, 100%; background-position: 50% 50%, 50% 50%; animation: aurora 32s ease-in-out infinite reverse; mix-blend-mode: difference; opacity: 0.9; background-attachment: fixed; }
      @media (prefers-color-scheme: dark) {
        .hero-aurora,
        .hero-aurora::after { background-image: var(--dark-gradient), var(--aurora); }
        .hero-aurora { mix-blend-mode: lighten; opacity: 0.45; }
      }
      .floating-badge { animation: float 6s ease-in-out infinite; }
      .hero-copy { position: relative; z-index: 2; min-height: clamp(420px, 68vh, 680px); display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 1.5rem; }
      .hero-description { min-height: 3.2rem; display: flex; align-items: center; justify-content: center; text-align: center; }
      .pulse-indicator { width: 10px; height: 10px; border-radius: 999px; background: #6366f1; position: relative; }
      .pulse-indicator::after { content: ""; position: absolute; inset: 0; border-radius: inherit; background: rgba(99, 102, 241, 0.4); animation: pulse 2s ease-out infinite; }
      .glow-card { position: relative; border-radius: 24px; padding: 28px; background: rgba(255, 255, 255, 0.8); border: 1px solid rgba(99, 102, 241, 0.12); box-shadow: 0 25px 45px rgba(79, 70, 229, 0.08); overflow: hidden; transform: perspective(1000px) rotateX(var(--tilt-x, 0deg)) rotateY(var(--tilt-y, 0deg)); transition: transform 0.3s ease, box-shadow 0.3s ease; }
      .glow-card::before { content: ""; position: absolute; inset: -1px; border-radius: inherit; background: radial-gradient(circle at 0% 0%, rgba(79, 70, 229, 0.35), transparent 55%); opacity: 0; transition: opacity 0.4s ease; }
      .glow-card:hover::before { opacity: 1; }
      .glow-card:hover { box-shadow: 0 35px 65px rgba(79, 70, 229, 0.18); }
      .glow-card .icon-wrapper { width: 52px; height: 52px; border-radius: 16px; display: flex; align-items: center; justify-content: center; background: linear-gradient(135deg, rgba(79, 70, 229, 0.12), rgba(129, 140, 248, 0.32)); color: #312e81; margin-bottom: 18px; }
      .chat-thread { margin-top: 3rem; display: flex; flex-direction: column; gap: 1.5rem; }
      .chat-row { display: flex; width: 100%; }
      .chat-row.justify-end { justify-content: flex-end; }
      .chat-row.justify-start { justify-content: flex-start; }
      .chat-entry { display: flex; align-items: flex-start; gap: 0.85rem; max-width: 580px; width: 100%; }
      .chat-entry.flex-row-reverse { flex-direction: row-reverse; }
      .chat-avatar { width: 42px; height: 42px; border-radius: 999px; display: flex; align-items: center; justify-content: center; box-shadow: 0 12px 24px rgba(15, 23, 42, 0.15); }
      .chat-avatar.user { background: linear-gradient(135deg, #0f172a, #1e293b); color: #fff; }
      .chat-avatar.assistant { background: linear-gradient(135deg, rgba(79, 70, 229, 0.9), rgba(129, 140, 248, 0.9)); color: #fff; }
      .chat-bubble { padding: 18px 22px; border-radius: 22px; background: rgba(248, 250, 252, 0.95); font-size: 0.97rem; line-height: 1.68; color: #0f172a; box-shadow: 0 18px 32px rgba(15, 23, 42, 0.12); border: 1px solid rgba(148, 163, 184, 0.12); }
      .chat-bubble.user { background: linear-gradient(135deg, rgba(15, 23, 42, 0.92), rgba(30, 41, 59, 0.92)); color: #e2e8f0; border-color: rgba(71, 85, 105, 0.35); }
      .chat-bubble.assistant { background: linear-gradient(135deg, rgba(255, 255, 255, 0.95), rgba(241, 245, 249, 0.95)); color: #1e293b; border-color: rgba(99, 102, 241, 0.18); }
      .chat-text { margin: 0; font-size: 0.95rem; }
      .glass-panel { background: rgba(15, 23, 42, 0.85); color: #e0e7ff; border-radius: 24px; padding: 32px; border: 1px solid rgba(148, 163, 184, 0.2); box-shadow: 0 35px 65px rgba(15, 23, 42, 0.45); }
      .glass-panel input { background: rgba(15, 23, 42, 0.55); border: 1px solid rgba(148, 163, 184, 0.4); color: inherit; }
      .glass-panel input::placeholder { color: rgba(226, 232, 240, 0.55); }
      .glass-panel button { background: #e0e7ff; color: #1f2937; }
      .info-panel { background: rgba(255, 255, 255, 0.88); border-radius: 24px; padding: 32px; border: 1px solid rgba(99, 102, 241, 0.15); box-shadow: 0 25px 45px rgba(79, 70, 229, 0.1); }
      .info-panel code { background: rgba(15, 23, 42, 0.08); padding: 0.25rem 0.5rem; border-radius: 0.75rem; font-size: 0.85rem; }
      .badge-soft { display: inline-flex; align-items: center; justify-content: center; padding: 0.4rem 0.85rem; border-radius: 999px; background: rgba(79, 70, 229, 0.12); color: #3730a3; font-size: 0.75rem; font-weight: 600; letter-spacing: 0.04em; }
      .pending-badge { display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.4rem 0.75rem; border-radius: 999px; font-size: 0.75rem; letter-spacing: 0.05em; text-transform: uppercase; background: rgba(99, 102, 241, 0.15); color: #312e81; font-weight: 600; }
      .pending-card code { background: rgba(79, 70, 229, 0.12); color: #312e81; border-radius: 0.75rem; padding: 0.25rem 0.5rem; }
      .section-title { font-size: clamp(2rem, 3vw, 2.8rem); font-weight: 700; color: #0f172a; text-align: center; margin-bottom: 1.5rem; }
      .section-subtitle { color: #475569; max-width: 640px; margin: 0 auto 3rem; text-align: center; }
      footer p { color: rgba(226, 232, 240, 0.9); }
      nav a { color: #475569; transition: color 0.2s ease; }
      nav a:hover { color: #312e81; }
      @keyframes aurora { 0% { background-position: 50% 50%, 50% 50%; } 50% { background-position: 46% 54%, 54% 46%; } 100% { background-position: 50% 50%, 50% 50%; } }
      @keyframes blink { 0%, 49% { opacity: 1; } 50%, 100% { opacity: 0; } }
      @keyframes float { 0% { transform: translateY(0); } 50% { transform: translateY(-10px); } 100% { transform: translateY(0); } }
      @keyframes gradientShift { 0% { transform: translate3d(0, 0, 0) scale(1); opacity: 0.55; } 50% { transform: translate3d(12px, -16px, 0) scale(1.1); opacity: 0.85; } 100% { transform: translate3d(-14px, 10px, 0) scale(1); opacity: 0.55; } }
      @keyframes pulse { 0% { transform: scale(1); opacity: 1; } 100% { transform: scale(2.4); opacity: 0; } }
      @media (max-width: 768px) {
        .chat-entry { max-width: 100%; }
        .chat-bubble { font-size: 0.92rem; padding: 16px 18px; }
      }
      @media (prefers-reduced-motion: reduce) {
        [data-animate] { opacity: 1 !important; transform: none !important; }
        [data-tilt] { transform: none !important; }
        [data-typewriter]::after { display: none !important; }
        .word-fade { opacity: 1 !important; transform: none !important; }
        .floating-badge { animation: none !important; }
      }
    </style>
  </head>
  <body class="bg-white text-gray-900">
    <header class="sticky top-0 z-40 bg-white/85 backdrop-blur border-b border-slate-100">
      <div class="max-w-6xl mx-auto px-6">
        <div class="flex items-center justify-between py-4 gap-3">
          <a href="/" class="flex items-center gap-3">
            <span class="w-10 h-10 rounded-xl bg-slate-900 text-white flex items-center justify-center font-bold shadow-lg">${escapeHtml(
              appInitial
            )}</span>
            <span class="text-lg font-semibold text-slate-900">${escapeHtml(appName)}</span>
          </a>
          <!--<div class="flex items-center gap-5">
            <nav class="hidden md:flex items-center gap-4 text-sm font-medium text-slate-600">
              <a href="#features" class="hover:text-slate-900 transition">Features</a>
              <a href="#how-it-works" class="hover:text-slate-900 transition">How it works</a>
              <a href="#overview" class="hover:text-slate-900 transition">Clients</a>
            </nav>
            ${headerAction}
          </div>-->
        </div>
      </div>
    </header>
    <main>
      ${heroSection}
      ${featureSection}
      ${howItWorksSection}
    </main>
    ${footerSection}
    ${firebaseModal}
    ${authStateScript}
    ${firebaseSnippet}
    ${animationScript}
  </body>
</html>
  `;
};
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

const prepareAuthorizationDetails = async (params: AuthorizationParams) => {
  let client = await findClientById(params.client_id);
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
  const appRecord = await findAppByResourceLocal(params.resource);
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
  const validScopes = validateScopes(appRecord, requestedScopes);
  if (validScopes.length === 0) {
    throw new AuthorizationRequestError(
      400,
      "Invalid scope",
      `<p class="danger">Requested scopes are not supported.</p>`
    );
  }
  const canonicalScopes = canonicalizeScopes(validScopes);
  if (client.app_uuid !== appRecord.id) {
    console.info(
      "[oauth/authorize] client app mismatch detected",
      sanitizeForLogging({
        clientId: client.client_id,
        currentAppId: client.app_uuid,
        targetAppId: appRecord.id,
        resource: params.resource,
        requestedScopes: canonicalScopes,
      })
    );
    client = await moveClientToApp(
      client.client_id,
      appRecord.id,
      canonicalScopes
    );
  }
  const authRequest: PendingAuthRequest = {
    response_type: params.response_type,
    client_id: params.client_id,
    redirect_uri: params.redirect_uri,
    scope: canonicalScopes,
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

const renderPaymentRequiredPage = (options: {
  appName: string;
  paymentLink: string;
  startedAt?: string;
  priceLabel?: string;
}): string => {
  const priceBlock = options.priceLabel
    ? `<p class="text-sm font-semibold">Price: ${escapeHtml(options.priceLabel)}</p>`
    : "";
  const intro = `
    <h1>Payment required</h1>
    <p>You need an active purchase to use <strong>${escapeHtml(options.appName)}</strong>.</p>
    ${priceBlock}
    <p>Please complete the payment in the new tab. This page will automatically continue once your purchase is confirmed.</p>
    <p><a href="${escapeHtml(options.paymentLink)}" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:0.5rem;padding:0.65rem 1.25rem;background:#2563eb;color:#fff;border-radius:999px;text-decoration:none;font-weight:600;">Open payment page</a></p>
  `;
  const started =
    options.startedAt && options.startedAt.length > 0
      ? `<p class="text-sm">Waiting since ${escapeHtml(options.startedAt)}.</p>`
      : "";
  const script = `
    <script>
      (function () {
        const STATUS_ENDPOINT = "/auth/payment-status";
        const RETRY_DELAY = 5000;
        let stopped = false;
        async function poll() {
          if (stopped) return;
          try {
            const response = await fetch(STATUS_ENDPOINT, {
              credentials: "same-origin",
              headers: {
                "Cache-Control": "no-cache"
              }
            });
            if (!response.ok) {
              throw new Error("Failed to check payment status.");
            }
            const payload = await response.json();
            if (payload?.paid) {
              stopped = true;
              window.location.assign("/auth/payment-resume");
              return;
            }
          } catch (error) {
            console.warn("Payment status check failed", error);
          }
          setTimeout(poll, RETRY_DELAY);
        }
        poll();
      })();
    </script>
  `;
  const body = `
    ${intro}
    ${started}
    <p class="text-sm">You can refresh this page after completing the payment if it doesn't continue automatically.</p>
  `;
  return renderPage("Payment required", body, { scripts: script });
};

const issueCodeAndRedirect = async (
  req: express.Request,
  res: express.Response,
  userUuid: string,
  authRequest: PendingAuthRequest
): Promise<void> => {
  const paymentDecision = await ensurePaymentAccess(
    req,
    userUuid,
    authRequest
  );
  if (!paymentDecision.allowed) {
    if ("error" in paymentDecision) {
      res
        .status(500)
        .send(
          renderPage(
            "Payment verification failed",
            `<p class="danger">${escapeHtml(paymentDecision.error)}</p>`
          )
        );
    } else {
      res.redirect(paymentDecision.redirectPath);
    }
    return;
  }

  try {
    const redirectUrl = await completeAuthorizationRequest(
      req,
      userUuid,
      authRequest
    );
    res.redirect(redirectUrl);
  } catch (error) {
    console.error("Failed to finalize authorization session", error);
    res
      .status(500)
      .send(
        renderPage(
          "Session error",
          `<p class="danger">We were unable to finalize the session. Please try again.</p>`
        )
      );
  }
};

const authorizePostSchema = authorizationQuerySchema.extend({
  email: z.string().email().optional(),
  password: z.string().min(8).optional(),
  decision: z.enum(["approve", "deny"]).optional(),
});

const firebaseSessionRequestSchema = z.object({
  idToken: z.string().min(1, "idToken cannot be empty"),
  resume: authorizationQuerySchema.optional(),
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

const previewTokenRequestSchema = z
  .object({
    client_id: z.string().min(1, "client_id is required"),
    user_uuid: z.string().uuid().optional(),
    email: z.string().email().optional(),
    sub: z.string().min(1).optional(),
    resource: z.string().url().optional(),
  })
  .superRefine((value, ctx) => {
    if (!value.user_uuid && !value.email && !value.sub) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Provide user_uuid, email, or sub to populate the token subject.",
        path: ["user_uuid"],
      });
    }
  });

app.get("/", async (req, res) => {
  const clientIdParam = req.query.client_id;
  let clientId =
    typeof clientIdParam === "string" && clientIdParam.trim().length > 0
      ? clientIdParam.trim()
      : undefined;
  const mcpUrlParam = req.query.mcpUrl;
  const mcpUrl =
    typeof mcpUrlParam === "string" && mcpUrlParam.trim().length > 0
      ? mcpUrlParam.trim()
      : undefined;

  const authRequest = req.session.authRequest;
  if (!clientId && authRequest) {
    clientId = authRequest.client_id;
  }

  const overviewOptions: AppOverviewOptions = {};
  if (clientId) {
    overviewOptions.clientId = clientId;
  }
  if (mcpUrl) {
    overviewOptions.mcpUrl = mcpUrl;
  }

  let currentUserEmail: string | undefined;
  if (req.session.userUuid) {
    try {
      const currentUser = await findUserByUuid(req.session.userUuid);
      if (currentUser) {
        currentUserEmail = currentUser.email;
      } else {
        req.session.userUuid = undefined;
      }
    } catch (error) {
      console.error("Failed to load current user from session", error);
    }
  }

  let pendingAuthSummary: AppOverviewOptions["pendingAuth"];
  let shouldAutoOpenFirebase = !currentUserEmail;
  let authResumePayload: AuthResumePayload | undefined;

  if (clientId) {
    try {
      const clientRecord = await findClientById(clientId);
      if (!clientRecord) {
        overviewOptions.error = `No client record found for client_id ${clientId}.`;
      } else {
        overviewOptions.client = clientRecord;
        try {
          const appRecord = await findAppByUuid(clientRecord.app_uuid);
          if (!appRecord) {
            overviewOptions.error = "No application record found for the client.";
          } else {
            overviewOptions.app = appRecord;
          }
        } catch (error) {
          console.error("Failed to load app by uuid", error);
          overviewOptions.error = "Failed to load app information, please try again later.";
        }
      }
    } catch (error) {
      console.error("Failed to load client by id", error);
      overviewOptions.error = "Failed to load client information, please try again later.";
    }
  }

  if (mcpUrl) {
    try {
      const appRecord = await findAppByResourceLocal(mcpUrl);
      if (appRecord) {
        if (!overviewOptions.app) {
          overviewOptions.app = appRecord;
        }
      } else if (!clientId && !overviewOptions.error) {
        overviewOptions.error = `No application record found for MCP URL ${mcpUrl}.`;
      }
    } catch (error) {
      console.error("Failed to load app by MCP URL", error);
      if (!overviewOptions.error) {
        overviewOptions.error = "Failed to load app information, please try again later.";
      }
    }
  }

  if (!overviewOptions.app && !mcpUrl) {
    try {
      const apps = await listApps();
      const defaultAppRecord = selectDefaultApp(apps) ?? apps[0];
      if (defaultAppRecord) {
        overviewOptions.app = defaultAppRecord;
      }
    } catch (error) {
      console.error("Failed to load apps for landing page content", error);
    }
  }

  if (authRequest) {
    shouldAutoOpenFirebase = true;
    const clientName =
      overviewOptions.client?.client_name ??
      overviewOptions.client?.client_id ??
      authRequest.client_id;
    pendingAuthSummary = {
      clientName,
      redirectUri: authRequest.redirect_uri,
      scopes: authRequest.scope,
    };
    authResumePayload = {
      response_type: authRequest.response_type,
      client_id: authRequest.client_id,
      redirect_uri: authRequest.redirect_uri,
      scope: authRequest.scope.join(" "),
      state: authRequest.state,
      code_challenge: authRequest.code_challenge,
      code_challenge_method: authRequest.code_challenge_method,
      resource: authRequest.resource,
    };
  }

  if (pendingAuthSummary) {
    overviewOptions.pendingAuth = pendingAuthSummary;
  }
  if (authResumePayload) {
    overviewOptions.authResume = authResumePayload;
  }
  overviewOptions.autoOpenFirebase = shouldAutoOpenFirebase;
  if (currentUserEmail) {
    overviewOptions.currentUserEmail = currentUserEmail;
  }

  const landingPage = renderLandingPage(overviewOptions);
  res.send(landingPage);
});

app.get("/auth/login", (req, res) => {
  const clientIdParam = req.query.client_id;
  const clientId =
    typeof clientIdParam === "string" && clientIdParam.length > 0
      ? clientIdParam
      : undefined;
  const target = clientId
    ? `/?client_id=${encodeURIComponent(clientId)}`
    : "/";
  res.redirect(target);
});

app.post("/auth/login", async (req, res) => {
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
  const sessionAppId = await resolveSessionAppId(req);
  if (!sessionAppId) {
    return res
      .status(400)
      .send(
        renderPage(
          "Login failed",
          `<p class="danger">Unable to determine the application context for this login. Please start the sign-in flow from the app's authorization link.</p>`
        )
      );
  }
  const user = await findUserByEmail(email.toLowerCase(), {
    appId: sessionAppId,
    fallbackToAny: false,
  });
  if (!user?.password_hash || !verifyPassword(password, user.password_hash)) {
    return res
      .status(401)
      .send(renderPage("Login failed", `<p class="danger">Incorrect email or password.</p>`));
  }
  req.session.userUuid = user.uuid;
  return res.redirect("/");
});

app.get("/auth/register", (req, res) => {
  const clientIdParam = req.query.client_id;
  const clientId =
    typeof clientIdParam === "string" && clientIdParam.length > 0
      ? clientIdParam
      : undefined;
  const target = clientId
    ? `/?client_id=${encodeURIComponent(clientId)}`
    : "/";
  res.redirect(target);
});

app.post("/auth/register", async (req, res) => {
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
  const sessionAppId = await resolveSessionAppId(req);
  if (!sessionAppId) {
    return res
      .status(400)
      .send(
        renderPage(
          "Registration failed",
          `<p class="danger">Unable to determine the application context for this registration. Please start the sign-up flow from the app's authorization link.</p>`
        )
      );
  }
  if (
    await findUserByEmail(email, {
      appId: sessionAppId,
      fallbackToAny: false,
    })
  ) {
    return res
      .status(409)
      .send(
        renderPage(
          "Registration failed",
          `<p class="danger">This email address is already registered for this app.</p>`
        )
      );
  }
  const passwordHash = hashPassword(parsed.data.password);
  const user = await createUser(email, passwordHash, parsed.data.displayName, {
    appId: sessionAppId,
    authProvider: "local",
  });
  req.session.userUuid = user.uuid;
  return res.redirect("/");
});

app.post("/auth/firebase/session", async (req, res) => {
  if (!CONFIG.firebaseClientConfig?.apiKey) {
    return res.status(503).json({
      ok: false,
      error: "Firebase is not configured, cannot use popup login.",
    });
  }
  const parsed = firebaseSessionRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      ok: false,
      error: "Invalid request parameters, missing idToken.",
    });
  }

  try {
    const { idToken, resume } = parsed.data;
    const account = await verifyFirebaseIdToken(idToken);
    const email = account.email.toLowerCase();

    if (!req.session.authRequest && resume) {
      try {
        const { authRequest } = await prepareAuthorizationDetails(resume);
        req.session.authRequest = authRequest;
      } catch (error) {
        console.warn("Failed to resume authorization request from Firebase payload", error);
      }
    }

    const sessionAppId = await resolveSessionAppId(req);
    if (!sessionAppId) {
      return res.status(400).json({
        ok: false,
        error:
          "Unable to determine the application context for this login. Please relaunch the authorization flow.",
      });
    }

    let user = await findUserByEmail(email, {
      appId: sessionAppId,
      fallbackToAny: false,
    });
    if (!user) {
      const randomPassword = createRandomPassword();
      const passwordHash = hashPassword(randomPassword);
      user = await createUser(email, passwordHash, account.displayName, {
        appId: sessionAppId,
        authProvider: "firebase",
        firebaseUid: account.uid,
      });
    }
    req.session.userUuid = user.uuid;

    const activeAuthRequest = req.session.authRequest;

    if (activeAuthRequest) {
      const paymentDecision = await ensurePaymentAccess(
        req,
        user.uuid,
        activeAuthRequest
      );
      if (!paymentDecision.allowed) {
        if ("error" in paymentDecision) {
          return res.status(500).json({
            ok: false,
            error: paymentDecision.error,
          });
        }
        return res.json({
          ok: true,
          redirect: paymentDecision.redirectPath,
        });
      }
      try {
        const redirectUrl = await completeAuthorizationRequest(
          req,
          user.uuid,
          activeAuthRequest
        );
        return res.json({ ok: true, redirect: redirectUrl });
      } catch (error) {
        console.error(
          "Failed to issue authorization code after Firebase login",
          error
        );
        return res.status(500).json({
          ok: false,
          error: "Failed to issue authorization code, please try again later.",
        });
      }
    }

    try {
      await persistSession(req);
    } catch (error) {
      console.error("Failed to persist session after Firebase login", error);
      return res
        .status(500)
        .json({ ok: false, error: "Failed to persist session, please try again later." });
    }

    return res.json({ ok: true });
  } catch (error) {
    console.error("Failed to validate Firebase session", error);
    return res.status(401).json({
      ok: false,
      error:
        error instanceof Error
          ? error.message
          : "Firebase login verification failed, please try again later.",
    });
  }
});

app.get("/auth/payment-required", async (req, res) => {
  const pending = req.session.pendingPayment;
  const userUuid = req.session.userUuid;
  const authRequest = req.session.authRequest;
  if (!pending || !userUuid || !authRequest) {
    if (pending) {
      req.session.pendingPayment = undefined;
      try {
        await persistSession(req);
      } catch (error) {
        console.warn("Failed to persist session while clearing pending payment", error);
      }
    }
    return res.redirect("/");
  }

  try {
    const hasPayment = await userHasActivePayment(pending.appId, userUuid);
    if (hasPayment) {
      req.session.pendingPayment = undefined;
      try {
        await persistSession(req);
      } catch (error) {
        console.warn("Failed to persist session after confirming payment", error);
      }
      return res.redirect("/auth/payment-resume");
    }
  } catch (error) {
    console.error("Failed to check payment status during payment-required", error);
    return res
      .status(500)
      .send(
        renderPage(
          "Payment verification failed",
          `<p class="danger">We were unable to verify your payment status. Please try again later.</p>`
        )
      );
  }

  let paymentLink = pending.paymentLink;
  let appName = pending.appName;
  let paymentModel = pending.paymentModel;
  let appRecord: App | undefined;
  try {
    appRecord = await findAppByUuid(pending.appId);
    if (!appName && appRecord?.name) {
      appName = appRecord.name;
    }
    if (!paymentModel && appRecord?.payment_model) {
      paymentModel = appRecord.payment_model;
    }
  } catch (error) {
    console.warn("Failed to reload app information for payment-required", error);
  }

  if (!paymentLink) {
    try {
      if (paymentModel?.model === "subscription" && appRecord) {
        const sessionInfo = await createPaymentSession(userUuid, appRecord);
        paymentLink = sessionInfo.url;
        req.session.pendingPayment = {
          ...pending,
          paymentLink,
          sessionId: sessionInfo.sessionId,
          startedAt: new Date().toISOString(),
          paymentModel,
          userUuid,
          appName,
        };
        await persistSession(req);
      } else if (appRecord?.payment_link) {
        paymentLink = appRecord.payment_link;
      }
    } catch (error) {
      console.error("Failed to refresh payment session", error);
      return res
        .status(500)
        .send(
          renderPage(
            "Payment unavailable",
            `<p class="danger">Unable to start the payment session. Please try again later.</p>`
          )
        );
    }
  }

  if (!paymentLink) {
    req.session.pendingPayment = undefined;
    try {
      await persistSession(req);
    } catch (error) {
      console.warn("Failed to persist session while clearing invalid payment link", error);
    }
    return res
      .status(500)
      .send(
        renderPage(
          "Payment unavailable",
          `<p class="danger">This application does not have a payment link configured. Please contact the administrator.</p>`
        )
      );
  }

  return res.send(
    renderPaymentRequiredPage({
      appName: appName ?? "this app",
      paymentLink,
      startedAt: pending.startedAt,
      priceLabel: formatPriceLabel(paymentModel ?? appRecord?.payment_model),
    })
  );
});

app.get("/auth/payment-status", async (req, res) => {
  const pending = req.session.pendingPayment;
  const userUuid = req.session.userUuid;
  if (
    !pending ||
    !userUuid ||
    (pending.userUuid && pending.userUuid !== userUuid)
  ) {
    return res.json({ ok: true, paid: false, pending: false });
  }
  try {
    const hasPayment = await userHasActivePayment(pending.appId, userUuid);
    if (hasPayment) {
      req.session.pendingPayment = undefined;
      try {
        await persistSession(req);
      } catch (error) {
        console.warn("Failed to persist session after payment polling succeeded", error);
      }
      return res.json({ ok: true, paid: true });
    }
    return res.json({ ok: true, paid: false, pending: true });
  } catch (error) {
    console.error("Failed to check payment status via polling endpoint", error);
    return res
      .status(500)
      .json({ ok: false, error: "Unable to verify payment status." });
  }
});

app.get("/auth/payment-resume", async (req, res) => {
  const authRequest = req.session.authRequest;
  const userUuid = req.session.userUuid;
  if (!authRequest || !userUuid) {
    return res.redirect("/");
  }
  await issueCodeAndRedirect(req, res, userUuid, authRequest);
});

app.get("/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/oauth/authorize", async (req, res) => {
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
    const { authRequest, app } = await prepareAuthorizationDetails(parsed.data);
    req.session.authRequest = authRequest;

    if (req.session.userUuid) {
      const user = await findUserByUuid(req.session.userUuid);
      if (user?.app_id === app.id) {
        await issueCodeAndRedirect(req, res, user.uuid, authRequest);
        return;
      }
      req.session.userUuid = undefined;
    }

    try {
      await persistSession(req);
    } catch (error) {
      console.error(
        "Failed to persist session before redirecting to home",
        error
      );
      return res.status(500).send(
        renderPage(
          "Server error",
          `<p class="danger">Failed to persist authorization session, please try again later.</p>`
        )
      );
    }

    const homeTarget = `/?client_id=${encodeURIComponent(
      authRequest.client_id
    )}`;
    return res.redirect(homeTarget);
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

app.post("/oauth/authorize", async (req, res) => {
  const parsed = authorizePostSchema.safeParse(req.body);
  if (!parsed.success) {
    const sessionAuth = req.session.authRequest;
    if (sessionAuth) {
      const [client, appRecord] = await Promise.all([
        findClientById(sessionAuth.client_id),
        findAppByResourceLocal(sessionAuth.resource),
      ]);
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
      await prepareAuthorizationDetails(oauthParams);
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
      try {
        await persistSession(req);
        return res.redirect(redirect.toString());
      } catch (err) {
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

    const user = await findUserByEmail(email.toLowerCase(), {
      appId: app.id,
      fallbackToAny: false,
    });
    if (!user?.password_hash || !verifyPassword(password, user.password_hash)) {
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
    await issueCodeAndRedirect(req, res, user.uuid, authRequest);
    return;
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

app.post("/oauth/preview-token", async (req, res) => {
  const parsed = previewTokenRequestSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      error: "invalid_request",
      error_description: "Malformed preview token request.",
      details: parsed.error.flatten(),
    });
  }

  const { client_id, user_uuid, email, sub, resource } = parsed.data;
  const normalizedEmail = email?.toLowerCase();
  logHttpEvent("POST", req.originalUrl, "request", {
    clientId: client_id,
    userUuid: user_uuid,
    hasEmail: Boolean(normalizedEmail),
    hasSub: Boolean(sub),
  });

  const client = await findClientById(client_id);
  if (!client) {
    return res.status(400).json({
      error: "invalid_client",
      error_description: "Unknown client_id.",
    });
  }

  const appRecord = await findAppByUuid(client.app_uuid);
  if (!appRecord) {
    return res.status(500).json({
      error: "server_error",
      error_description: "Associated app configuration is unavailable.",
    });
  }

  let subject = sub;
  let emailClaim = normalizedEmail;

  if (user_uuid) {
    const user = await findUserByUuid(user_uuid);
    if (!user) {
      return res.status(404).json({
        error: "invalid_user",
        error_description: "User not found for the provided user_uuid.",
      });
    }
    subject = user.uuid;
    emailClaim = user.email;
  } else if (normalizedEmail) {
    const existing = await findUserByEmail(normalizedEmail, {
      appId: appRecord.id,
      fallbackToAny: false,
    });
    if (existing) {
      subject = existing.uuid;
      emailClaim = existing.email;
    }
  }

  if (!subject) {
    subject = "preview-user";
  }

  const resolvedResource =
    resource?.trim() ||
    appRecord.resource_uri?.trim() ||
    appRecord.mcp_server_ids
      .map((value) => value.trim())
      .find((value) => value) ||
    CONFIG.issuer;

  const scope = "openid profile email apps.read";
  try {
    const { token, expiresAt } = await issueAccessToken(
      subject,
      client.client_id,
      resolvedResource,
      scope,
      emailClaim
    );
    const protectedHeader = decodeProtectedHeader(token);
    console.info("[preview-token] issued token", {
      clientId: client.client_id,
      subject,
      resource: resolvedResource,
      scope,
      hasEmailClaim: Boolean(emailClaim),
      expiresAt,
      kid: protectedHeader.kid,
      alg: protectedHeader.alg,
    });
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = Math.max(0, expiresAt - now);
    return res.json({
      access_token: token,
      token_type: "Bearer",
      expires_in: expiresIn,
      scope,
      resource: resolvedResource,
    });
  } catch (error) {
    console.error("Failed to issue preview token", error);
    return res.status(500).json({
      error: "server_error",
      error_description: "Unable to issue preview token.",
    });
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
    logHttpEvent("POST", req.originalUrl, "request", {
      grantType: data.grant_type,
      clientId: data.client_id,
      redirectUri: data.redirect_uri,
      hasCodeVerifier: Boolean(data.code_verifier),
      resource: data.resource,
    });
    const client = await findClientById(data.client_id);
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

    const codeRecord = await consumeAuthorizationCode(data.code);
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
    console.info(
      "[oauth/token] authorization_code pre-issue state",
      sanitizeForLogging({
        clientId: client.client_id,
        grantType: data.grant_type,
        redirectUri: data.redirect_uri,
        resource,
        scope: codeRecord.scope,
        userUuid: codeRecord.user_uuid,
        codeIssuedAt: codeRecord.expires_at - 600,
        codeExpiresAt: codeRecord.expires_at,
      })
    );
    const digest = crypto
      .createHash("sha256")
      .update(data.code_verifier)
      .digest("base64url");
    if (digest !== codeRecord.code_challenge) {
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "code_verifier does not match code_challenge." });
    }
    const user = await findUserByUuid(codeRecord.user_uuid);
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
    await storeAccessToken({
      token: accessToken,
      user_uuid: user.uuid,
      client_id: client.client_id,
      scope: codeRecord.scope,
      resource,
      expires_at: expiresAt,
    });
    const refresh = createRefreshToken();
    await storeRefreshToken({
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
    logHttpEvent("POST", req.originalUrl, "request", {
      grantType: data.grant_type,
      clientId: data.client_id,
      hasClientSecret: Boolean(data.client_secret),
      hasRefreshToken: Boolean(data.refresh_token),
    });
    const client = await findClientById(data.client_id);
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
    const stored = await findRefreshToken(data.refresh_token);
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
      await revokeRefreshToken(data.refresh_token);
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "Refresh token expired." });
    }
    const user = await findUserByUuid(stored.user_uuid);
    if (!user) {
      await revokeRefreshToken(data.refresh_token);
      return res
        .status(400)
        .json({ error: "invalid_grant", error_description: "User no longer exists." });
    }
    console.info(
      "[oauth/token] refresh_token pre-issue state",
      sanitizeForLogging({
        clientId: client.client_id,
        grantType: data.grant_type,
        refreshTokenUser: stored.user_uuid,
        refreshTokenScope: stored.scope,
        refreshTokenResource: stored.resource,
        refreshTokenExpiresAt: stored.expires_at,
      })
    );
    const { token: newAccessToken, expiresAt } = await issueAccessToken(
      user.uuid,
      client.client_id,
      stored.resource,
      stored.scope,
      user.email
    );
    await storeAccessToken({
      token: newAccessToken,
      user_uuid: user.uuid,
      client_id: client.client_id,
      scope: stored.scope,
      resource: stored.resource,
      expires_at: expiresAt,
    });
    const refreshed = createRefreshToken();
    await storeRefreshToken({
      token: refreshed.token,
      user_uuid: user.uuid,
      client_id: client.client_id,
      scope: stored.scope,
      resource: stored.resource,
      expires_at: refreshed.expiresAt,
    });
    await revokeRefreshToken(data.refresh_token);
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

app.post("/oauth/register", async (req, res) => {
  console.info(
    "[oauth/register] incoming payload",
    sanitizeForLogging(req.body)
  );
  const parsed = registrationSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "invalid_request", error_description: "Malformed registration payload." });
  }
  const data = parsed.data;
  const apps = await listApps();
  console.info(
    "[oauth/register] loaded apps for matching",
    sanitizeForLogging(
      apps.map((app) => ({
        id: app.id,
        name: app.name,
        resource_uri: app.resource_uri,
        mcp_server_ids: app.mcp_server_ids,
      }))
    )
  );
  let appRecord: App | undefined;
  const resource = data.resource;
  if (resource) {
    appRecord = apps.find((app) => appMatchesResource(app, resource));
    console.info(
      "[oauth/register] matching result",
      sanitizeForLogging({
        resource,
        matchedAppId: appRecord?.id,
        matchedBy: appRecord
          ? appMatchesResource(appRecord, resource)
            ? "resource_or_mcp_server_id"
            : "unknown"
          : "none",
      })
    );
    if (!appRecord) {
      appRecord = selectDefaultApp(apps);
      console.info(
        "[oauth/register] fallback app selection",
        sanitizeForLogging({
          reason: "no_direct_match",
          fallbackAppId: appRecord?.id,
        })
      );
    }
    if (!appRecord) {
      return res.status(400).json({
        error: "invalid_target",
        error_description: "Unknown resource.",
      });
    }
  } 
  else {
    const configuredAppId = CONFIG.defaultAppId?.trim();
    if (configuredAppId) {
      appRecord = apps.find((app) => app.id === configuredAppId);
      console.info(
        "[oauth/register] resource missing, using configured default app",
        sanitizeForLogging({
          fallbackAppId: appRecord?.id,
          configuredAppId,
        })
      );
    }
    if (!appRecord) {
      appRecord = selectDefaultApp(apps);
      console.info(
        "[oauth/register] resource missing, selectDefaultApp fallback",
        sanitizeForLogging({
          fallbackAppId: appRecord?.id,
        })
      );
    }
    if (!appRecord) {
      return res.status(400).json({
        error: "invalid_target",
        error_description:
          "resource is required when a default app is not configured.",
      });
    }
    // console.log("appRecord from selectDefaultApp", appRecord);
    // if (!appRecord) {
    //   return res.status(400).json({
    //     error: "invalid_target",
    //     error_description: "resource is required for multi-MCP registration.",
    //   });
    // }
  }
  const requestedScopeString = data.scope ?? appRecord.default_scopes;
  const requestedScopes = requestedScopeString.split(" ").filter(Boolean);
  const validScopes = validateScopes(appRecord, requestedScopes);
  if (validScopes.length !== requestedScopes.length) {
    return res.status(400).json({
      error: "invalid_scope",
      error_description: "One or more requested scopes are not supported.",
    });
  }
  const canonicalScopes = canonicalizeScopes(validScopes);
  const scope = canonicalScopes.join(" ");
  console.info(
    "[oauth/register] creating client",
    sanitizeForLogging({
      appId: appRecord.id,
      appName: appRecord.name,
      resourceUsed: resource ?? appRecord.resource_uri,
      payload: {
        client_name: data.client_name,
        application_type: data.application_type,
        grant_types: data.grant_types,
        redirect_uris: data.redirect_uris,
        scope,
        token_endpoint_auth_method: data.token_endpoint_auth_method,
      },
    })
  );
  const client = await createClient({
    client_name: data.client_name,
    application_type: data.application_type,
    grant_types: data.grant_types,
    redirect_uris: data.redirect_uris,
    scope,
    token_endpoint_auth_method: data.token_endpoint_auth_method,
    app_uuid: appRecord.uuid,
  });
  const response: Record<string, unknown> = {
    client_id: client.client_id,
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
  if (client.client_secret) {
    response.client_secret = client.client_secret;
  }
  return res.status(201).json(response);
});

app.get("/oauth/client/:clientId", async (req, res) => {
  const authHeader = req.header("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "invalid_client",
      error_description: "Missing registration access token.",
    });
  }
  const token = authHeader.slice("Bearer ".length);
  const client = await findClientByRegistrationAccessToken(token);
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
    const user = await findUserByUuid(payload.sub);
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

app.get("/.well-known/openid-configuration", async (_req, res) => {
  const metadata = await buildAuthorizationServerMetadata();
  res.json({
    ...metadata,
    userinfo_endpoint: `${CONFIG.issuer}/oauth/userinfo`,
    subject_types_supported: ["public"],
    claims_supported: ["sub", "email"],
    service_documentation: CONFIG.docsUrl,
  });
});

app.get("/.well-known/oauth-authorization-server", async (_req, res) => {
  res.json(await buildAuthorizationServerMetadata());
});

app.get("/.well-known/oauth-protected-resource", async (req, res) => {
  const resource = req.query.resource;
  if (typeof resource === "string") {
    const appRecord = await findAppByResourceLocal(resource);
    if (!appRecord) {
      return res.status(404).json({
        error: "invalid_resource",
        error_description: "No app is registered for the requested resource.",
      });
    }
    return res.json(buildResourceMetadata(appRecord));
  }
  const apps = await listApps();
  if (apps.length === 0) {
    return res.status(404).json({
      error: "no_apps_configured",
      error_description:
        "No MCP apps are registered. Please provision at least one app.",
    });
  }
  return res.json({
    resources: apps.map((app) => buildResourceMetadata(app)),
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
  const apps = await listApps();
  if (apps.length === 0) {
    console.warn(
      "No MCP apps registered yet. OAuth flows will fail until an app is provisioned."
    );
  }
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
