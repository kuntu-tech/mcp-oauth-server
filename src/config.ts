import fs from "fs";
import path from "path";
import dotenv from "dotenv";

dotenv.config();

const projectRoot = process.cwd();
const dataDirectory = path.join(projectRoot, "data");

if (!fs.existsSync(dataDirectory)) {
  fs.mkdirSync(dataDirectory, { recursive: true });
}

export const CONFIG = {
  baseUrl: process.env.BASE_URL ?? "http://localhost:4000",
  resourceServerUrl:
    process.env.RESOURCE_SERVER_URL ?? "https://example.com/mcp",
  issuer:
    process.env.ISSUER_URL ??
    (process.env.BASE_URL ?? "http://localhost:4000"),
  sessionSecret: process.env.SESSION_SECRET ?? "change-me-in-production",
  defaultScopes:
    process.env.DEFAULT_SCOPES ??
    "openid profile email apps.basic apps.purchase",
  accessTokenTtlSeconds: Number(process.env.ACCESS_TOKEN_TTL ?? 3600),
  refreshTokenTtlSeconds: Number(process.env.REFRESH_TOKEN_TTL ?? 60 * 60 * 24),
  dataDir: dataDirectory,
  databasePath: path.join(dataDirectory, "auth.db"),
  jwksPath: path.join(dataDirectory, "jwks.json"),
  adminContact: process.env.ADMIN_CONTACT ?? "mailto:admin@example.com",
  docsUrl:
    process.env.DOCUMENTATION_URL ??
    "https://developers.openai.com/apps-sdk/build/auth",
};

export const SUPPORTED_SCOPES = CONFIG.defaultScopes.split(" ").filter(Boolean);
