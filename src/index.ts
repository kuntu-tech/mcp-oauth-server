import crypto from "crypto";
import https from "https";
import express from "express";
import session from "express-session";
import morgan from "morgan";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { CONFIG } from "./config";
import {
  createClient,
  createUser,
  findAppByResource,
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
} from "./store";
import type { App, Client } from "./store";
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
        const openButtons = Array.from(
          document.querySelectorAll("[data-firebase-modal-trigger]")
        );
        const statusEl = document.getElementById("firebaseui-status");
        const container = document.getElementById("firebaseui-modal-container");
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
        openButtons.forEach((button) =>
          button.addEventListener("click", (event) => {
            event.preventDefault();
            showModal();
          })
        );

        const auth = firebase.auth();
        const ui =
          firebaseui.auth.AuthUI.getInstance() ??
          new firebaseui.auth.AuthUI(auth);
        let uiStarted = false;
        const providerConfig = ${JSON.stringify(CONFIG.firebaseUiProviders)};
        const providerIds = (providerConfig || []).map((provider) => {
          switch (provider) {
            case "google":
              return firebase.auth.GoogleAuthProvider.PROVIDER_ID;
            case "apple":
              return "apple.com";
            case "github":
              return firebase.auth.GithubAuthProvider
                ? firebase.auth.GithubAuthProvider.PROVIDER_ID
                : "github.com";
            case "microsoft":
              return "microsoft.com";
            case "twitter":
              return firebase.auth.TwitterAuthProvider
                ? firebase.auth.TwitterAuthProvider.PROVIDER_ID
                : "twitter.com";
            case "facebook":
              return firebase.auth.FacebookAuthProvider
                ? firebase.auth.FacebookAuthProvider.PROVIDER_ID
                : "facebook.com";
            case "email":
            default:
              return firebase.auth.EmailAuthProvider.PROVIDER_ID;
          }
        }).filter(Boolean);
        if (!providerIds.length) {
          providerIds.push(firebase.auth.EmailAuthProvider.PROVIDER_ID);
        }

        const uiConfig = {
          signInFlow: "popup",
          signInOptions: providerIds,
          tosUrl: "${CONFIG.docsUrl}",
          privacyPolicyUrl: "${CONFIG.privacyPolicyUrl}",
          callbacks: {
            signInSuccessWithAuthResult: async function (authResult) {
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
                console.log("payload", payload);
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
    }>;
  };

  let parsed: FirebaseLookupResponse;
  try {
    parsed = JSON.parse(responseBody) as FirebaseLookupResponse;
  } catch {
    throw new Error("Cannot parse Firebase return data.");
  }

  const user = parsed.users?.[0];
  if (!user?.email) {
    throw new Error("Firebase account missing email information.");
  }

  return {
    uid: user.localId ?? "",
    email: user.email,
    displayName: user.displayName ?? undefined,
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
      : "https://platform.openai.com/docs/apps";
  const contactLink =
    CONFIG.adminContact && CONFIG.adminContact.trim().length > 0
      ? CONFIG.adminContact
      : "mailto:admin@example.com";
  const heroTitle = "Smart App Name";
  const heroSubtitle =
    "One sentence introducing your app's core value, helping users quickly understand the product advantages";

  const features = [
    {
      icon: iconSparkles(),
      title: "Smart Analysis",
      description:
        "Based on advanced AI technology, providing deep insights and intelligent recommendations",
    },
    {
      icon: iconZap(),
      title: "Fast Response",
      description:
        "Millisecond-level response speed, instantly getting the information and answers you need",
    },
    {
      icon: iconShield(),
      title: "Secure & Reliable",
      description:
        "Enterprise-level security protection, safeguarding your data privacy and information security",
    },
    {
      icon: iconTrendingUp(),
      title: "Continuous Optimization",
      description:
        "Continuously learning and improving, providing increasingly accurate service experience",
    },
  ];

  const featuresHtml = features
    .map(
      (feature) => `
        <div class="p-6 bg-white/70 backdrop-blur-sm border border-slate-200 rounded-2xl shadow-sm hover:shadow-lg transition-shadow">
          <div class="w-12 h-12 bg-gray-900 text-white rounded-xl flex items-center justify-center mb-4">
            ${feature.icon}
          </div>
          <h3 class="text-xl font-semibold text-gray-900 mb-2">${escapeHtml(feature.title)}</h3>
          <p class="text-gray-600 text-sm md:text-base leading-relaxed">${escapeHtml(feature.description)}</p>
        </div>
      `
    )
    .join("");

  const conversations = [
    {
      type: "user" as const,
      message: "How can I quickly improve work efficiency?",
    },
    {
      type: "bot" as const,
      message:
        "Based on your needs, I suggest focusing on three key areas: 1. Use time management tools to plan daily tasks; 2. Adopt the Pomodoro technique to maintain focus; 3. Regularly review and optimize workflows. I can create a detailed implementation plan for you.",
    },
    {
      type: "user" as const,
      message: "Can you help me analyze current data trends?",
    },
    {
      type: "bot" as const,
      message:
        "Of course! Through analyzing your data, I found these key trends: overall growth rate of 23%, with mobile traffic growing fastest at 45%. I recommend focusing on optimizing mobile user experience, which could bring an additional 30% conversion improvement.",
    },
  ];

  const conversationHtml = conversations
    .map((conv) => {
      const isUser = conv.type === "user";
      const alignmentClass = isUser ? "justify-end" : "justify-start";
      const bubbleClass = isUser
        ? "bg-gray-900 text-white shadow-lg border border-gray-800"
        : "bg-white text-gray-800 shadow-lg border border-gray-200";
      const iconWrapperClass = isUser ? "bg-gray-800" : "bg-gray-900";
      const icon = isUser
        ? iconMessageCircle("w-5 h-5 text-white")
        : iconBot("w-5 h-5 text-white");
      return `
        <div class="flex ${alignmentClass}">
          <div class="flex items-start gap-3 max-w-2xl ${isUser ? "flex-row-reverse" : ""}">
            <div class="w-10 h-10 ${iconWrapperClass} rounded-full flex items-center justify-center shadow-md">
              ${icon}
            </div>
            <div class="px-6 py-4 rounded-2xl ${bubbleClass}">
              <p class="text-sm md:text-base leading-relaxed">${escapeHtml(conv.message)}</p>
            </div>
          </div>
        </div>
      `;
    })
    .join("");

  const pendingAuthSummary = pendingAuth
    ? `
      <div class="p-6 bg-indigo-50 border border-indigo-200 rounded-2xl shadow-sm mb-6">
        <p class="text-xs font-semibold uppercase tracking-wide text-indigo-600">Pending authorization request</p>
        <p class="mt-3 text-base text-indigo-900">
          The client <span class="font-semibold">${escapeHtml(
            pendingAuth.clientName
          )}</span> will be authorized with the following permissions, and will redirect back after completion:
        </p>
        <p class="mt-2 text-sm text-indigo-800 break-all">
          <code class="bg-white/60 px-1.5 py-0.5 rounded">${escapeHtml(
            pendingAuth.redirectUri
          )}</code>
        </p>
        <div class="mt-3 flex flex-wrap gap-2">
          ${pendingAuth.scopes
            .map(
              (scope) =>
                `<span class="px-3 py-1 text-xs font-medium rounded-full bg-indigo-100 text-indigo-700">${escapeHtml(
                  scope
                )}</span>`
            )
            .join("")}
        </div>
      </div>
    `
    : "";

  let clientDetails = `
    <div class="p-8 bg-white border border-gray-200 rounded-2xl shadow-sm">
      <h3 class="text-2xl font-semibold text-gray-900 mb-4">Application information</h3>
      <p class="text-gray-600 leading-relaxed">
        Use the query panel on the right to input <code class="px-1.5 py-0.5 bg-slate-100 rounded text-sm text-slate-700">client_id</code>, to view the resources and permissions bound to the client.
      </p>
    </div>
  `;

  if (clientId && !app && !client && !error) {
    clientDetails = `
      <div class="p-8 bg-white border border-gray-200 rounded-2xl shadow-sm">
        <h3 class="text-2xl font-semibold text-gray-900 mb-4">Client not found</h3>
        <p class="text-rose-600 text-base">
          No client record found for client_id <code class="px-1.5 py-0.5 bg-rose-50 rounded text-sm text-rose-700">${escapeHtml(
            clientId
          )}</code> client record.
        </p>
      </div>
    `;
  }

  if (error) {
    clientDetails = `
      <div class="p-8 bg-white border border-rose-200 rounded-2xl shadow-sm">
        <h3 class="text-2xl font-semibold text-gray-900 mb-4">Load failed</h3>
        <p class="text-rose-600 text-base">${escapeHtml(error)}</p>
      </div>
    `;
  }

  if (app && client) {
    const scopes = getAppScopes(app);
    const scopesList = scopes.length
      ? scopes
          .map(
            (scope) =>
              `<span class="inline-flex items-center justify-center px-3 py-1 bg-indigo-50 text-indigo-600 rounded-full text-xs font-medium">${escapeHtml(
                scope
              )}</span>`
          )
          .join("")
      : '<span class="text-sm text-gray-500">The application has not configured default scopes.</span>';
    const redirectList = client.redirect_uris.length
      ? client.redirect_uris
          .map(
            (uri) =>
              `<li class="text-sm text-gray-700 break-all"><code class="bg-slate-100 rounded px-1.5 py-0.5">${escapeHtml(
                uri
              )}</code></li>`
          )
          .join("")
      : '<li class="text-sm text-gray-500">The client has not configured redirect URIs.</li>';
    clientDetails = `
      <div class="p-8 bg-white border border-gray-200 rounded-2xl shadow-sm space-y-4">
        <div>
          <h3 class="text-2xl font-semibold text-gray-900 mb-1">${escapeHtml(app.name)}</h3>
          ${
            client.client_name
              ? `<p class="text-gray-600">Client name: <span class="font-medium text-gray-900">${escapeHtml(
                  client.client_name
                )}</span></p>`
              : ""
          }
        </div>
        <div class="grid md:grid-cols-2 gap-4">
          <div class="space-y-2">
            <p class="text-sm text-gray-500 uppercase tracking-wide">Client ID</p>
            <p class="text-base text-gray-900 break-all"><code class="bg-slate-100 rounded px-1.5 py-0.5">${escapeHtml(
              client.client_id
            )}</code></p>
          </div>
          <div class="space-y-2">
            <p class="text-sm text-gray-500 uppercase tracking-wide">Resource URI</p>
            <p class="text-base text-gray-900 break-all"><code class="bg-slate-100 rounded px-1.5 py-0.5">${escapeHtml(
              app.resource_uri
            )}</code></p>
          </div>
        </div>
        <div class="space-y-2">
          <p class="text-sm text-gray-500 uppercase tracking-wide">Default scopes</p>
          <div class="flex flex-wrap gap-2">${scopesList}</div>
        </div>
        <div class="space-y-2">
          <p class="text-sm text-gray-500 uppercase tracking-wide">Redirect URIs</p>
          <ul class="space-y-1">${redirectList}</ul>
        </div>
      </div>
    `;
  }

  const clientDetailsBlock = pendingAuthSummary + clientDetails;

  const firebaseSection = `
    <section id="firebase-auth" class="py-20 bg-gradient-to-b from-slate-900 via-slate-900 to-slate-950 text-white">
      <div class="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="grid md:grid-cols-2 gap-12 items-center">
          <div>
            <h2 class="text-3xl md:text-4xl font-bold mb-4">Firebase Sign in / Sign up</h2>
            <p class="text-slate-300 leading-relaxed mb-6">
              ${
                hasFirebase
                  ? "The Firebase login window will automatically pop up after page load; you can use the button below to reopen it at any time."
                  : "The Firebase configuration is missing, cannot display the FirebaseUI component. Please complete the environment variables and try again."
              }
            </p>
            <ul class="space-y-2 text-sm text-slate-300">
              <li>• Supports multiple Firebase providers (Email, Google, GitHub, etc.).</li>
              <li>• After successful login, the authorization process will continue automatically and redirect back to the client.</li>
              <li>• If you need to customize the callback, you can adjust it in <code class="bg-white/10 rounded px-1.5 py-0.5">config.ts</code>.</li>
            </ul>
          </div>
          <div class="bg-white text-gray-900 rounded-2xl shadow-2xl p-6 md:p-8 space-y-4">
            <p class="text-sm text-slate-600">
              After ready, click the button below to reopen the Firebase login window to switch accounts or re-verify.
            </p>
            <button
              type="button"
              data-firebase-modal-trigger
              class="inline-flex items-center justify-center w-full px-5 py-3 bg-gray-900 text-white rounded-lg font-semibold hover:bg-black transition-colors"
            >
              Open Firebase login window
            </button>
          </div>
        </div>
      </div>
    </section>
  `;

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
                <p class="text-sm font-semibold text-indigo-600">Firebase Sign in</p>
                <h3 class="text-lg font-bold text-gray-900 mt-1">Use Firebase Sign in</h3>
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
    <section id="hero" class="relative overflow-hidden">
      <div class="absolute inset-0 bg-gradient-to-br from-sky-100 via-white to-indigo-100"></div>
      <div class="absolute -top-24 -right-24 w-72 h-72 bg-sky-200 rounded-full blur-3xl opacity-70"></div>
      <div class="absolute -bottom-24 -left-10 w-80 h-80 bg-indigo-200 rounded-full blur-3xl opacity-60"></div>
      <div class="relative max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-24 md:py-32">
        <div class="max-w-3xl">
          <h1 class="text-4xl md:text-6xl font-bold text-gray-900 mb-6 leading-tight">
            ${escapeHtml(heroTitle)}
          </h1>
          <p class="text-lg md:text-2xl text-gray-600 mb-8 leading-relaxed">
            ${escapeHtml(heroSubtitle)}
          </p>
          <div class="flex flex-col sm:flex-row sm:items-center gap-4">
            <a href="${escapeHtml(
              docsUrl
            )}" target="_blank" rel="noopener noreferrer" class="inline-flex items-center justify-center gap-2 px-8 py-3 bg-gray-900 text-white font-semibold rounded-lg shadow-lg hover:bg-black transition-colors">
              <span>Use Now in ChatGPT</span>
              ${iconArrowRight("w-5 h-5")}
            </a>
          </div>
        </div>
      </div>
    </section>
  `;

  const featureSection = `
    <section id="features" class="py-20 bg-white">
      <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center max-w-2xl mx-auto mb-16">
          <h2 class="text-3xl md:text-4xl font-bold text-gray-900 mb-4">Core Features</h2>
          <p class="text-lg text-gray-600">
            Powerful features providing you with an exceptional experience
          </p>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
          ${featuresHtml}
        </div>
      </div>
    </section>
  `;

  const howItWorksSection = `
    <section id="how-it-works" class="py-20 bg-slate-50">
      <div class="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl md:text-4xl font-bold text-gray-900 mb-4">How It Works</h2>
        </div>
        <div class="space-y-6">
          ${conversationHtml}
        </div>
      </div>
    </section>
  `;

  const clientOverviewSection = `
    <section id="overview" class="py-20 bg-white">
      <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="grid lg:grid-cols-[1fr,1fr] gap-10">
          ${clientDetailsBlock}
          <div class="p-8 bg-slate-900 text-white rounded-2xl shadow-2xl">
            <h3 class="text-2xl font-semibold mb-4">Query client</h3>
            <p class="text-slate-300 text-sm leading-relaxed mb-6">
              Input the <span class="font-semibold">client_id</span> you want to view, to load the registration information and default scopes of the client.
            </p>
            <form method="get" action="/" class="space-y-4">
              <label class="block">
                <span class="text-sm text-slate-200 uppercase tracking-wide">Client ID</span>
                <input
                  type="text"
                  name="client_id"
                  value="${clientId ? escapeHtml(clientId) : ""}"
                  placeholder="Input client_id"
                  class="mt-1 w-full px-4 py-3 rounded-lg bg-white text-gray-900 placeholder:text-gray-400 border border-slate-200 focus:outline-none focus:ring-2 focus:ring-white/60"
                />
              </label>
              <button
                type="submit"
                class="w-full inline-flex items-center justify-center gap-2 px-6 py-3 bg-white text-gray-900 font-semibold rounded-lg hover:bg-slate-100 transition-colors"
              >
                View client details
              </button>
            </form>
            <p class="mt-6 text-xs text-slate-400 leading-relaxed">
              Tip: The <code class="bg-white/10 px-1.5 py-0.5 rounded text-white">?client_id=</code> parameter in the OAuth callback can also directly jump to the query results of this page.
            </p>
          </div>
        </div>
      </div>
    </section>
  `;

  const pricingSection = `
    <section id="pricing" class="py-20 bg-white">
      <div class="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="text-center mb-16">
          <h2 class="text-3xl md:text-4xl font-bold text-gray-900 mb-4">Pricing examples</h2>
          <p class="text-lg text-gray-600">Use the template content for reference, and replace it with the actual pricing strategy as needed.</p>
        </div>
        <div class="grid md:grid-cols-2 gap-6">
          <div class="bg-gray-50 border border-gray-200 rounded-2xl shadow-sm overflow-hidden">
            <div class="bg-gray-100 px-8 py-6 border-b border-gray-200 text-center">
              <h3 class="text-2xl font-bold text-gray-900">Free Plan</h3>
              <p class="text-gray-600 mt-2 text-sm">Experience basic capabilities, suitable for prototype verification</p>
            </div>
            <div class="px-8 py-10 space-y-6">
              <div class="text-center">
                <div class="flex items-baseline justify-center gap-2">
                  <span class="text-5xl font-bold text-gray-900">$0</span>
                  <span class="text-xl text-gray-500">/month</span>
                </div>
                <p class="text-sm text-gray-500 mt-2">Permanent free</p>
              </div>
              <ul class="space-y-3 text-gray-700 text-sm">
                <li class="flex items-start gap-3">
                  ${iconCheck("w-5 h-5 text-gray-900 flex-shrink-0 mt-0.5")}
                  <span>Experience basic OAuth authorization process</span>
                </li>
                <li class="flex items-start gap-3">
                  ${iconCheck("w-5 h-5 text-gray-900 flex-shrink-0 mt-0.5")}
                  <span>100 test calls per month</span>
                </li>
                <li class="flex items-start gap-3">
                  ${iconCheck("w-5 h-5 text-gray-900 flex-shrink-0 mt-0.5")}
                  <span>Community support and FAQ guidance</span>
                </li>
                <li class="flex items-start gap-3">
                  ${iconX("w-5 h-5 text-gray-300 flex-shrink-0 mt-0.5")}
                  <span class="text-gray-500">Advanced data analysis</span>
                </li>
                <li class="flex items-start gap-3">
                  ${iconX("w-5 h-5 text-gray-300 flex-shrink-0 mt-0.5")}
                  <span class="text-gray-500">Team collaboration capabilities</span>
                </li>
              </ul>
              <a class="block text-center w-full px-6 py-3 border border-gray-300 rounded-lg font-semibold text-gray-900 hover:bg-gray-200 transition-colors">
                Start now
              </a>
            </div>
          </div>
          <div class="bg-gray-900 text-white rounded-2xl shadow-xl overflow-hidden border border-gray-800 relative">
            <div class="absolute top-0 right-0 bg-white text-gray-900 px-4 py-1 text-sm font-semibold rounded-bl-xl shadow-md">
              Recommended
            </div>
            <div class="bg-black px-8 py-6 border-b border-gray-800 text-center">
              <div class="flex items-center justify-center gap-2 mb-2">
                ${iconCrown("w-5 h-5 text-gray-300")}
                <h3 class="text-2xl font-bold">Pro Plan</h3>
              </div>
              <p class="text-sm text-gray-300">Unlock all advanced features</p>
            </div>
            <div class="px-8 py-10 space-y-6">
              <div class="text-center">
                <div class="flex items-baseline justify-center gap-2">
                  <span class="text-5xl font-bold text-white">$29</span>
                  <span class="text-xl text-gray-400">/month</span>
                </div>
                <p class="text-sm text-gray-400 mt-2">Monthly subscription, can be cancelled at any time</p>
              </div>
              <ul class="space-y-3 text-gray-200 text-sm">
                <li class="flex items-start gap-3">
                  ${iconCheck("w-5 h-5 text-white flex-shrink-0 mt-0.5")}
                  <span>Unlimited sessions and token refreshes</span>
                </li>
                <li class="flex items-start gap-3">
                  ${iconCheck("w-5 h-5 text-white flex-shrink-0 mt-0.5")}
                  <span>Real-time resource server synchronization</span>
                </li>
                <li class="flex items-start gap-3">
                  ${iconCheck("w-5 h-5 text-white flex-shrink-0 mt-0.5")}
                  <span>Exclusive support and monitoring alerts</span>
                </li>
              </ul>
              <a class="block text-center w-full px-6 py-3 bg-white text-gray-900 rounded-lg font-semibold hover:bg-gray-100 transition-colors">
                Upgrade experience
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  `;

  const footerSection = `
    <footer class="bg-black text-white py-12">
      <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 text-center space-y-4">
        <p class="text-gray-400 text-sm">
          © ${new Date().getFullYear()} Auth Server. All rights reserved.
        </p>
        <p class="text-sm text-gray-500">
          If you need support, please contact <a href="${escapeHtml(
            contactLink
          )}" class="text-white font-semibold hover:text-gray-300 transition-colors">${escapeHtml(
    contactLink.replace(/^mailto:/, "")
  )}</a>
        </p>
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
    ? `
        <div class="flex items-center gap-3 text-sm text-gray-600">
          <span>Logged in: <span class="font-semibold text-gray-900">${escapeHtml(
            currentUserEmail
          )}</span></span>
          <button
            type="button"
            data-firebase-modal-trigger
            class="inline-flex items-center px-3 py-1.5 border border-gray-300 rounded-md hover:bg-gray-100 transition-colors"
          >
            Switch account
          </button>
        </div>
      `
    : `
        <button
          type="button"
          data-firebase-modal-trigger
          class="inline-flex items-center px-4 py-2 text-sm font-semibold border border-gray-300 rounded-lg hover:bg-gray-100 transition-colors"
        >
          Sign in experience
        </button>
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
      body { font-family: 'Inter', system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
      ::selection { background: rgba(79, 70, 229, 0.2); }
    </style>
  </head>
  <body class="bg-white text-gray-900">
    <header class="sticky top-0 z-40 bg-white/90 backdrop-blur border-b border-gray-100">
      <div class="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex items-center justify-between py-4">
          <a href="/" class="flex items-center gap-3">
            <span class="w-10 h-10 rounded-xl bg-gray-900 text-white flex items-center justify-center font-bold shadow-md">D</span>
            <span class="text-lg font-semibold text-gray-900">App Name</span>
          </a>
         
        </div>
      </div>
    </header>
    <main>
      ${heroSection}
      ${featureSection}
      ${howItWorksSection}
      ${clientOverviewSection}
      ${firebaseSection}
      ${pricingSection}
    </main>
    ${footerSection}
    ${firebaseModal}
    ${authStateScript}
    ${firebaseSnippet}
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
  const client = await findClientById(params.client_id);
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
  const appRecord = await findAppByResource(params.resource);
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

const issueCodeAndRedirect = async (
  req: express.Request,
  res: express.Response,
  userUuid: string,
  authRequest: PendingAuthRequest
): Promise<void> => {
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

app.get("/", async (req, res) => {
  const clientIdParam = req.query.client_id;
  let clientId =
    typeof clientIdParam === "string" && clientIdParam.trim().length > 0
      ? clientIdParam.trim()
      : undefined;

  const authRequest = req.session.authRequest;
  if (!clientId && authRequest) {
    clientId = authRequest.client_id;
  }

  const overviewOptions: AppOverviewOptions = {};
  if (clientId) {
    overviewOptions.clientId = clientId;
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
  const user = await findUserByEmail(email.toLowerCase());
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
  if (await findUserByEmail(email)) {
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
  const user = await createUser(email, passwordHash, parsed.data.displayName, {
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
    let user = await findUserByEmail(email);
    if (!user) {
      const randomPassword = createRandomPassword();
      const passwordHash = hashPassword(randomPassword);
      user = await createUser(email, passwordHash, account.displayName, {
        authProvider: "firebase",
        firebaseUid: account.uid,
      });
    }
    req.session.userUuid = user.uuid;

    if (!req.session.authRequest && resume) {
      try {
        const { authRequest } = await prepareAuthorizationDetails(resume);
        req.session.authRequest = authRequest;
      } catch (error) {
        console.warn("Failed to resume authorization request from Firebase payload", error);
      }
    }

    const activeAuthRequest = req.session.authRequest;

    if (activeAuthRequest) {
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
    const { authRequest } = await prepareAuthorizationDetails(parsed.data);
    req.session.authRequest = authRequest;

    if (req.session.userUuid) {
      const user = await findUserByUuid(req.session.userUuid);
      if (user) {
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
        findAppByResource(sessionAuth.resource),
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

    const user = await findUserByEmail(email.toLowerCase());
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
  console.log("raw registration payload", req.body);
  const parsed = registrationSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "invalid_request", error_description: "Malformed registration payload." });
  }
  const data = parsed.data;
  let appRecord: App | undefined;
  if (data.resource) {
    appRecord = await findAppByResource(data.resource);
    if (!appRecord) {
      return res.status(400).json({
        error: "invalid_target",
        error_description: "Unknown resource.",
      });
    }
  } else {
    const apps = await listApps();
    if (apps.length === 1) {
      appRecord = apps[0];
    } else {
      return res.status(400).json({
        error: "invalid_target",
        error_description: "resource is required for multi-MCP registration.",
      });
    }
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
  const scope = validScopes.join(" ");
  const client = await createClient({
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
    const appRecord = await findAppByResource(resource);
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
