import Database from "better-sqlite3";
import { CONFIG } from "./config";

const db = new Database(CONFIG.databasePath);
db.pragma("foreign_keys = ON");

const ISO_TIMESTAMP = "datetime('now')";

db.exec(
  `
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  display_name TEXT,
  created_at TEXT NOT NULL DEFAULT (${ISO_TIMESTAMP}),
  updated_at TEXT NOT NULL DEFAULT (${ISO_TIMESTAMP})
);

CREATE TABLE IF NOT EXISTS apps (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  resource_uri TEXT NOT NULL UNIQUE,
  default_scopes TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (${ISO_TIMESTAMP}),
  updated_at TEXT NOT NULL DEFAULT (${ISO_TIMESTAMP})
);

CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT NOT NULL UNIQUE,
  client_secret TEXT,
  client_name TEXT,
  token_endpoint_auth_method TEXT NOT NULL,
  application_type TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  scope TEXT,
  app_uuid TEXT NOT NULL,
  registration_access_token TEXT,
  registration_client_uri TEXT,
  client_id_issued_at INTEGER NOT NULL,
  client_secret_expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (${ISO_TIMESTAMP}),
  updated_at TEXT NOT NULL DEFAULT (${ISO_TIMESTAMP}),
  FOREIGN KEY (app_uuid) REFERENCES apps(uuid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS authorization_codes (
  code TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  resource TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (${ISO_TIMESTAMP}),
  FOREIGN KEY (user_uuid) REFERENCES users(uuid) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS access_tokens (
  token TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (${ISO_TIMESTAMP}),
  FOREIGN KEY (user_uuid) REFERENCES users(uuid) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token TEXT PRIMARY KEY,
  user_uuid TEXT NOT NULL,
  client_id TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (${ISO_TIMESTAMP}),
  FOREIGN KEY (user_uuid) REFERENCES users(uuid) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);
`
);

export default db;
