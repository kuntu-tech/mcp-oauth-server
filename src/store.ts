import crypto from "crypto";
import { randomUUID } from "crypto";
import db from "./db";
import { CONFIG, SUPPORTED_SCOPES } from "./config";

export interface User {
  uuid: string;
  email: string;
  password_hash: string;
  display_name?: string | null;
}

export interface App {
  uuid: string;
  name: string;
  resource_uri: string;
  default_scopes: string;
}

export interface Client {
  client_id: string;
  client_secret?: string | null;
  client_name?: string | null;
  token_endpoint_auth_method: string;
  application_type: string;
  redirect_uris: string[];
  grant_types: string[];
  scope?: string | null;
  app_uuid: string;
  registration_access_token?: string | null;
  registration_client_uri?: string | null;
  client_id_issued_at: number;
  client_secret_expires_at: number;
}

const userRowToUser = (row: any): User | undefined =>
  row
    ? {
        uuid: row.uuid,
        email: row.email,
        password_hash: row.password_hash,
        display_name: row.display_name,
      }
    : undefined;

export const findUserByEmail = (email: string): User | undefined => {
  const stmt = db.prepare("SELECT * FROM users WHERE email = ?");
  return userRowToUser(stmt.get(email));
};

export const findUserByUuid = (uuid: string): User | undefined => {
  const stmt = db.prepare("SELECT * FROM users WHERE uuid = ?");
  return userRowToUser(stmt.get(uuid));
};

export const createUser = (
  email: string,
  passwordHash: string,
  displayName?: string
): User => {
  const uuid = randomUUID();
  const insert = db.prepare(
    "INSERT INTO users (uuid, email, password_hash, display_name) VALUES (?, ?, ?, ?)"
  );
  insert.run(uuid, email, passwordHash, displayName ?? null);
  return {
    uuid,
    email,
    password_hash: passwordHash,
    display_name: displayName,
  };
};

const appRowToApp = (row: any): App | undefined =>
  row
    ? {
        uuid: row.uuid,
        name: row.name,
        resource_uri: row.resource_uri,
        default_scopes: row.default_scopes,
      }
    : undefined;

export const findAppByResource = (resourceUri: string): App | undefined => {
  const stmt = db.prepare("SELECT * FROM apps WHERE resource_uri = ?");
  return appRowToApp(stmt.get(resourceUri));
};

export const findAppByUuid = (uuid: string): App | undefined => {
  const stmt = db.prepare("SELECT * FROM apps WHERE uuid = ?");
  return appRowToApp(stmt.get(uuid));
};

export const ensureDefaultApp = (): App => {
  const existing = findAppByResource(CONFIG.resourceServerUrl);
  if (existing) {
    return existing;
  }
  const uuid = randomUUID();
  const insert = db.prepare(
    "INSERT INTO apps (uuid, name, resource_uri, default_scopes) VALUES (?, ?, ?, ?)"
  );
  insert.run(
    uuid,
    "Primary OpenAI Apps Connector",
    CONFIG.resourceServerUrl,
    CONFIG.defaultScopes
  );
  return {
    uuid,
    name: "Primary OpenAI Apps Connector",
    resource_uri: CONFIG.resourceServerUrl,
    default_scopes: CONFIG.defaultScopes,
  };
};

const clientRowToClient = (row: any): Client | undefined =>
  row
    ? {
        client_id: row.client_id,
        client_secret: row.client_secret,
        client_name: row.client_name,
        token_endpoint_auth_method: row.token_endpoint_auth_method,
        application_type: row.application_type,
        redirect_uris: JSON.parse(row.redirect_uris ?? "[]"),
        grant_types: JSON.parse(row.grant_types ?? "[]"),
        scope: row.scope,
        app_uuid: row.app_uuid,
        registration_access_token: row.registration_access_token,
        registration_client_uri: row.registration_client_uri,
        client_id_issued_at: row.client_id_issued_at,
        client_secret_expires_at: row.client_secret_expires_at,
      }
    : undefined;

export const findClientById = (clientId: string): Client | undefined => {
  const stmt = db.prepare("SELECT * FROM clients WHERE client_id = ?");
  return clientRowToClient(stmt.get(clientId));
};

export const findClientByRegistrationAccessToken = (
  token: string
): Client | undefined => {
  const stmt = db.prepare(
    "SELECT * FROM clients WHERE registration_access_token = ?"
  );
  return clientRowToClient(stmt.get(token));
};

export const createClient = (
  client: Omit<Client, "client_id" | "client_id_issued_at" | "client_secret_expires_at">
): Client => {
  const clientId = randomUUID();
  const clientSecret =
    client.token_endpoint_auth_method === "none"
      ? null
      : client.client_secret || crypto.randomBytes(32).toString("hex");
  const issuedAt = Math.floor(Date.now() / 1000);
  const secretExpiresAt =
    client.token_endpoint_auth_method === "none"
      ? 0
      : issuedAt + CONFIG.refreshTokenTtlSeconds;
  const registrationAccessToken =
    client.registration_access_token ?? crypto.randomBytes(32).toString("hex");
  const registrationClientUri =
    client.registration_client_uri ??
    `${CONFIG.issuer}/oauth/client/${clientId}`;

  const insert = db.prepare(
    `INSERT INTO clients (
      client_id,
      client_secret,
      client_name,
      token_endpoint_auth_method,
      application_type,
      redirect_uris,
      grant_types,
      scope,
      app_uuid,
      registration_access_token,
      registration_client_uri,
      client_id_issued_at,
      client_secret_expires_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );

  insert.run(
    clientId,
    clientSecret,
    client.client_name ?? null,
    client.token_endpoint_auth_method,
    client.application_type,
    JSON.stringify(client.redirect_uris),
    JSON.stringify(client.grant_types),
    client.scope ?? null,
    client.app_uuid,
    registrationAccessToken,
    registrationClientUri,
    issuedAt,
    secretExpiresAt
  );

  return {
    client_id: clientId,
    client_secret: clientSecret ?? undefined,
    client_name: client.client_name,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    application_type: client.application_type,
    redirect_uris: client.redirect_uris,
    grant_types: client.grant_types,
    scope: client.scope,
    app_uuid: client.app_uuid,
    registration_access_token: registrationAccessToken,
    registration_client_uri: registrationClientUri,
    client_id_issued_at: issuedAt,
    client_secret_expires_at: secretExpiresAt,
  };
};

export const updateClientScopes = (clientId: string, scope: string) => {
  const stmt = db.prepare(
    "UPDATE clients SET scope = ?, updated_at = datetime('now') WHERE client_id = ?"
  );
  stmt.run(scope, clientId);
};

export interface AuthorizationCode {
  code: string;
  user_uuid: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: "S256";
  resource: string;
  expires_at: number;
  consumed: number;
}

const codeRowToCode = (row: any): AuthorizationCode | undefined =>
  row
    ? {
        code: row.code,
        user_uuid: row.user_uuid,
        client_id: row.client_id,
        redirect_uri: row.redirect_uri,
        scope: row.scope,
        code_challenge: row.code_challenge,
        code_challenge_method: row.code_challenge_method,
        resource: row.resource,
        expires_at: row.expires_at,
        consumed: row.consumed,
      }
    : undefined;

export const persistAuthorizationCode = (code: AuthorizationCode) => {
  const insert = db.prepare(
    `INSERT INTO authorization_codes
    (code, user_uuid, client_id, redirect_uri, scope, code_challenge, code_challenge_method, resource, expires_at, consumed)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  insert.run(
    code.code,
    code.user_uuid,
    code.client_id,
    code.redirect_uri,
    code.scope,
    code.code_challenge,
    code.code_challenge_method,
    code.resource,
    code.expires_at,
    code.consumed
  );
};

export const consumeAuthorizationCode = (
  codeValue: string
): AuthorizationCode | undefined => {
  const stmt = db.prepare(
    "SELECT * FROM authorization_codes WHERE code = ? AND consumed = 0"
  );
  const record = stmt.get(codeValue);
  if (!record) {
    return undefined;
  }
  const deleteStmt = db.prepare(
    "UPDATE authorization_codes SET consumed = 1 WHERE code = ?"
  );
  deleteStmt.run(codeValue);
  return codeRowToCode(record);
};

export interface StoredToken {
  token: string;
  user_uuid: string;
  client_id: string;
  scope: string;
  resource: string;
  expires_at: number;
}

export const storeAccessToken = (token: StoredToken) => {
  const insert = db.prepare(
    `INSERT INTO access_tokens (token, user_uuid, client_id, scope, resource, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  );
  insert.run(
    token.token,
    token.user_uuid,
    token.client_id,
    token.scope,
    token.resource,
    token.expires_at
  );
};

export const storeRefreshToken = (token: StoredToken) => {
  const insert = db.prepare(
    `INSERT INTO refresh_tokens (token, user_uuid, client_id, scope, resource, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  );
  insert.run(
    token.token,
    token.user_uuid,
    token.client_id,
    token.scope,
    token.resource,
    token.expires_at
  );
};

export const findRefreshToken = (token: string): StoredToken | undefined => {
  const stmt = db.prepare("SELECT * FROM refresh_tokens WHERE token = ?");
  const row = stmt.get(token);
  return row
    ? {
        token: row.token,
        user_uuid: row.user_uuid,
        client_id: row.client_id,
        scope: row.scope,
        resource: row.resource,
        expires_at: row.expires_at,
      }
    : undefined;
};

export const revokeRefreshToken = (token: string) => {
  const stmt = db.prepare("DELETE FROM refresh_tokens WHERE token = ?");
  stmt.run(token);
};

export const validateScopes = (requestedScopes: string[]): string[] => {
  return requestedScopes.filter((scope) => SUPPORTED_SCOPES.includes(scope));
};
