import fs from "fs";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

const projectRoot = process.cwd();
const dataDirectory = path.join(projectRoot, "data");

if (!fs.existsSync(dataDirectory)) {
  fs.mkdirSync(dataDirectory, { recursive: true });
}

type FirebaseClientConfig = {
  apiKey?: string;
  authDomain?: string;
  projectId?: string;
  storageBucket?: string;
  messagingSenderId?: string;
  appId?: string;
  measurementId?: string;
};

const firebaseClientConfig: FirebaseClientConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
  measurementId: process.env.FIREBASE_MEASUREMENT_ID,
};

const hasFirebaseClientConfig = Object.values(firebaseClientConfig).some(
  (value) => Boolean(value)
);

const firebaseUiProviders = (process.env.FIREBASE_SIGN_IN_PROVIDERS ?? "email")
  .split(",")
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);

const defaultMcpServerId = process.env.DEFAULT_MCP_SERVER_ID;
const defaultAppId = process.env.DEFAULT_APP_ID;

const supabaseConfig = {
  url: process.env.SUPABASE_URL,
  serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
  anonKey: process.env.SUPABASE_ANON_KEY,
  schema: process.env.SUPABASE_DB_SCHEMA ?? "public",
};

export const CONFIG = {
  baseUrl: process.env.BASE_URL ?? "http://localhost:4000",
  issuer:
    process.env.ISSUER_URL ??
    (process.env.BASE_URL ?? "http://localhost:4000"),
  sessionSecret: process.env.SESSION_SECRET ?? "change-me-in-production",
  accessTokenTtlSeconds: Number(process.env.ACCESS_TOKEN_TTL ?? 3600),
  refreshTokenTtlSeconds: Number(process.env.REFRESH_TOKEN_TTL ?? 60 * 60 * 24),
  dataDir: dataDirectory,
  jwksPath: path.join(dataDirectory, "jwks.json"),
  adminContact: process.env.ADMIN_CONTACT ?? "mailto:admin@example.com",
  docsUrl:
    process.env.DOCUMENTATION_URL ??
    "https://developers.openai.com/apps-sdk/build/auth",
  privacyPolicyUrl:
    process.env.PRIVACY_POLICY_URL ??
    "https://developers.openai.com/apps-sdk/data-usage#privacy",
  defaultMcpServerId,
  defaultAppId,
  firebaseClientConfig: hasFirebaseClientConfig
    ? firebaseClientConfig
    : undefined,
  firebaseUiProviders:
    firebaseUiProviders.length > 0 ? firebaseUiProviders : ["email"],
  supabase: supabaseConfig,
};
