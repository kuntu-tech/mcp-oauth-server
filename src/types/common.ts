/**
 * Common type definitions used across the application
 */

export type RenderOptions = {
  scripts?: string;
};

export type AuthResumePayload = {
  response_type: "code";
  client_id: string;
  redirect_uri: string;
  scope: string;
  state?: string;
  code_challenge: string;
  code_challenge_method: "S256";
  resource: string;
};

export type LandingPageContent = {
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

export type RouteLogDetails = Record<string, unknown>;

export type PaymentRequirement = {
  appName: string;
  paymentLink: string;
  startedAt?: string;
  priceLabel?: string;
};

export type PaymentGateDecision =
  | { allowed: true }
  | { allowed: false; payment: PaymentRequirement }
  | { allowed: false; error: string };

export type SessionPendingPayment = {
  appId: string;
  appName?: string;
  paymentLink?: string;
  sessionId?: string;
  startedAt?: string;
  paymentModel?: unknown;
  userUuid?: string;
};

export type PaymentSessionApiResponse = {
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

export type FirebaseUiMode = "login" | "register" | "auth";

export type FirebaseAccountRecord = {
  uid: string;
  email?: string;
  displayName?: string;
};

export type PendingAuthRequest = {
  response_type: "code";
  client_id: string;
  redirect_uri: string;
  scope: string[];
  state?: string;
  code_challenge: string;
  code_challenge_method: "S256";
  resource: string;
};

/**
 * Custom error class for authorization request errors
 */
export class AuthorizationRequestError extends Error {
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

/**
 * Options for rendering the landing page
 */
export type AppOverviewOptions = {
  clientId?: string;
  mcpUrl?: string;
  app?: import("../store").App;
  client?: import("../store").Client;
  error?: string;
  pendingAuth?: {
    clientName: string;
    redirectUri: string;
    scopes: string[];
  };
  autoOpenFirebase?: boolean;
  currentUserEmail?: string;
  authResume?: AuthResumePayload;
  pendingPayment?: PaymentRequirement;
  autoOpenPayment?: boolean;
};

