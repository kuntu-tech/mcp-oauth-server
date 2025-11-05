import crypto from "crypto";
import { randomUUID } from "crypto";
import supabase from "./db";
import { CONFIG } from "./config";

const DEFAULT_SCOPE_FALLBACK = ["openid", "profile", "email"];

type Nullable<T> = T | null | undefined;

type AppRow = {
  id: string;
  name: string;
  config?: string | null;
  status?: string | null;
  payment_link?: string | null;
  mcp_server_ids?: string[] | string | null;
  app_meta_info?: unknown;
  created_at?: string | null;
  updated_at?: string | null;
};

type AppUserRow = {
  id: string;
  email?: string | null;
  password_hash?: string | null;
  name?: string | null;
  avatar_url?: string | null;
  auth_provider?: string | null;
  provider_user_id?: string | null;
  firebase_uid?: string | null;
  app_id?: string | null;
  last_login_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

type AuthorizationCodeRow = {
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
};

type TokenRow = {
  token: string;
  user_uuid: string;
  client_id: string;
  scope: string;
  resource: string;
  expires_at: number;
};

type AppUserPaymentRow = {
  id: string;
  app_id?: string | null;
  user_uuid?: string | null;
  status?: string | null;
  expires_at?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

type AppConfigClient = {
  client_id?: string;
  client_secret?: string | null;
  client_name?: string | null;
  application_type?: string | null;
  redirect_uris?: Nullable<string[] | string>;
  grant_types?: Nullable<string[] | string>;
  scope?: string | null;
  token_endpoint_auth_method?: string | null;
  registration_access_token?: string | null;
  registration_client_uri?: string | null;
  client_id_issued_at?: number | null;
  client_secret_expires_at?: number | null;
  resource_uri?: string | null;
  resource?: string | null;
  default_scopes?: Nullable<string[] | string>;
};

type AppConfig = {
  resource_uri?: string | null;
  resourceUri?: string | null;
  resource?: string | null;
  default_scopes?: Nullable<string[] | string>;
  oauth?: {
    client_id?: string;
    client_secret?: string;
    client_name?: string;
    application_type?: string;
    redirect_uris?: Nullable<string[] | string>;
    grant_types?: Nullable<string[] | string>;
    scope?: string;
    token_endpoint_auth_method?: string;
    registration_access_token?: string;
    registration_client_uri?: string;
    client_id_issued_at?: number;
    client_secret_expires_at?: number;
    resource_uri?: string;
    resource?: string;
    default_scopes?: Nullable<string[] | string>;
    clients?: AppConfigClient[];
    client?: AppConfigClient;
  };
  clients?: AppConfigClient[];
  authorization_codes?: AppAuthorizationCodeRecord[];
  [key: string]: unknown;
};

export interface User {
  uuid: string;
  email: string;
  password_hash?: string | null;
  display_name?: string | null;
  app_id?: string | null;
  auth_provider?: string | null;
  firebase_uid?: string | null;
  provider_user_id?: string | null;
}

export interface App {
  id: string;
  uuid: string;
  name: string;
  resource_uri: string;
  payment_link?: string | null;
  mcp_server_ids: string[];
  default_scopes: string;
  status?: string | null;
  config: AppConfig;
  meta_info?: AppMetaInfo;
}

export type AppMetaInfo = {
  run_id?: string;
  task_id?: string;
  chatAppMeta?: {
    name?: string;
    tagline?: string;
    description?: string;
    coreFeatures?: Array<{
      title?: string;
      summary?: string;
    }>;
    highlightedQuestions?: Array<{
      question?: string;
      simulatedAnswer?: string;
    }>;
  };
};

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

type AppAuthorizationCodeRecord = {
  code: string;
  user_uuid: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
  resource: string;
  expires_at: number;
  consumed: number;
};

export interface StoredToken {
  token: string;
  user_uuid: string;
  client_id: string;
  scope: string;
  resource: string;
  expires_at: number;
}

const normalizeScopeInput = (value: unknown): string[] => {
  if (!value) {
    return [];
  }
  if (Array.isArray(value)) {
    return value
      .map((item) => String(item).trim())
      .filter(Boolean);
  }
  if (typeof value === "string") {
    return value
      .split(/[\s,]+/)
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
};

export const canonicalizeScopes = (scopes: string[]): string[] => {
  const unique = Array.from(
    new Set(scopes.map((scope) => scope.trim()).filter(Boolean))
  );
  return unique.sort((a, b) => a.localeCompare(b));
};

export const canonicalScopeString = (value: unknown): string => {
  return canonicalizeScopes(normalizeScopeInput(value)).join(" ");
};

const parseAppConfig = (config?: string | null): AppConfig => {
  if (!config) {
    return {};
  }
  try {
    const parsed = JSON.parse(config) as AppConfig;
    return typeof parsed === "object" && parsed !== null ? parsed : {};
  } catch (error) {
    console.warn("Failed to parse app config JSON", error);
    return {};
  }
};

const serializeAppConfig = (config: AppConfig): string =>
  JSON.stringify(config, null, 2);

const resourceFromConfig = (config: AppConfig): string | undefined => {
  return (
    config.resource_uri ??
    config.resourceUri ??
    config.resource ??
    config.oauth?.resource_uri ??
    config.oauth?.resource ??
    config.oauth?.client?.resource_uri ??
    config.oauth?.client?.resource
  )?.trim();
};

const normalizeStringArray = (value: unknown): string[] => {
  if (!value) {
    return [];
  }
  if (Array.isArray(value)) {
    return value
      .map((item) => String(item).trim())
      .filter(Boolean);
  }
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value);
      if (Array.isArray(parsed)) {
        return normalizeStringArray(parsed);
      }
    } catch {
      // Treat plain string value as a single entry.
      return [value.trim()].filter(Boolean);
    }
    return value
      .split(/[\s,]+/)
      .map((item) => item.trim())
      .filter(Boolean);
  }
  return [];
};

const defaultScopesFromConfig = (config: AppConfig): string[] => {
  const scopes =
    normalizeScopeInput(config.default_scopes) ||
    normalizeScopeInput(config.oauth?.default_scopes) ||
    normalizeScopeInput(config.oauth?.client?.default_scopes);
  if (scopes.length > 0) {
    return canonicalizeScopes(scopes);
  }
  const scopeString =
    config.oauth?.scope ?? config.oauth?.client?.scope ?? undefined;
  const normalized = normalizeScopeInput(scopeString);
  if (normalized.length > 0) {
    return canonicalizeScopes(normalized);
  }
  return [];
};

const coerceStringArray = (value: Nullable<string[] | string>): string[] => {
  if (!value) {
    return [];
  }
  if (Array.isArray(value)) {
    return value.map((item) => String(item));
  }
  const trimmed = String(value).trim();
  if (!trimmed) {
    return [];
  }
  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) {
      return parsed.map((item) => String(item));
    }
  } catch {
    // fall back to comma/space separated
  }
  return trimmed.split(/[\s,]+/).map((item) => item.trim()).filter(Boolean);
};

const appConfigClients = (config: AppConfig): AppConfigClient[] => {
  const clients: AppConfigClient[] = [];

  if (Array.isArray(config.clients)) {
    clients.push(...config.clients);
  }

  if (config.oauth?.clients && Array.isArray(config.oauth.clients)) {
    clients.push(...config.oauth.clients);
  }

  const oauthAsClient: AppConfigClient | undefined =
    config.oauth?.client_id || config.oauth?.client
      ? {
          client_id: config.oauth?.client?.client_id ?? config.oauth?.client_id,
          client_secret:
            config.oauth?.client?.client_secret ?? config.oauth?.client_secret,
          client_name:
            config.oauth?.client?.client_name ?? config.oauth?.client_name,
          application_type:
            config.oauth?.client?.application_type ??
            config.oauth?.application_type,
          redirect_uris:
            config.oauth?.client?.redirect_uris ??
            config.oauth?.redirect_uris ??
            [],
          grant_types:
            config.oauth?.client?.grant_types ??
            config.oauth?.grant_types ??
            [],
          scope: config.oauth?.client?.scope ?? config.oauth?.scope,
          token_endpoint_auth_method:
            config.oauth?.client?.token_endpoint_auth_method ??
            config.oauth?.token_endpoint_auth_method,
          registration_access_token:
            config.oauth?.client?.registration_access_token ??
            config.oauth?.registration_access_token,
          registration_client_uri:
            config.oauth?.client?.registration_client_uri ??
            config.oauth?.registration_client_uri,
          client_id_issued_at:
            config.oauth?.client?.client_id_issued_at ??
            config.oauth?.client_id_issued_at,
          client_secret_expires_at:
            config.oauth?.client?.client_secret_expires_at ??
            config.oauth?.client_secret_expires_at,
          resource_uri:
            config.oauth?.client?.resource_uri ?? config.oauth?.resource_uri,
          resource: config.oauth?.client?.resource ?? config.oauth?.resource,
          default_scopes:
            config.oauth?.client?.default_scopes ??
            config.oauth?.default_scopes,
        }
      : undefined;

  if (oauthAsClient?.client_id) {
    clients.push(oauthAsClient);
  }

  return clients
    .filter(
      (client): client is AppConfigClient =>
        Boolean(client && client.client_id && String(client.client_id).trim())
    )
    .map((client) => ({
      ...client,
      client_id: client.client_id
        ? String(client.client_id).trim()
        : undefined,
    }));
};

const dedupeClients = (clients: AppConfigClient[]): AppConfigClient[] => {
  const seen = new Map<string, AppConfigClient>();
  clients.forEach((client) => {
    if (client.client_id) {
      seen.set(client.client_id, { ...client });
    }
  });
  return Array.from(seen.values());
};

const isDynamicClient = (client: AppConfigClient): boolean => {
  return Boolean(
    client.registration_client_uri ||
      client.registration_access_token ||
      client.client_id_issued_at
  );
};

const withClientsInConfig = (
  config: AppConfig,
  clients: AppConfigClient[]
): AppConfig => {
  const deduped = dedupeClients(clients);
  const primary = deduped[deduped.length - 1];

  const nextOauth: NonNullable<AppConfig["oauth"]> = {
    ...(config.oauth ?? {}),
    clients: deduped,
  };

  if (primary) {
    nextOauth.client = {
      ...(primary as AppConfigClient),
    };
    nextOauth.client_id = primary.client_id;
    nextOauth.client_secret =
      primary.client_secret ?? nextOauth.client_secret ?? undefined;
    nextOauth.client_name =
      primary.client_name ?? nextOauth.client_name ?? undefined;
    nextOauth.application_type =
      primary.application_type ?? nextOauth.application_type ?? undefined;
    nextOauth.redirect_uris =
      primary.redirect_uris ?? nextOauth.redirect_uris ?? [];
    nextOauth.grant_types =
      primary.grant_types ?? nextOauth.grant_types ?? [];
    nextOauth.scope = primary.scope ?? nextOauth.scope ?? undefined;
    nextOauth.token_endpoint_auth_method =
      primary.token_endpoint_auth_method ??
      nextOauth.token_endpoint_auth_method ??
      undefined;
    nextOauth.registration_access_token =
      primary.registration_access_token ??
      nextOauth.registration_access_token ??
      undefined;
    nextOauth.registration_client_uri =
      primary.registration_client_uri ??
      nextOauth.registration_client_uri ??
      undefined;
    nextOauth.client_id_issued_at =
      primary.client_id_issued_at ??
      nextOauth.client_id_issued_at ??
      undefined;
    nextOauth.client_secret_expires_at =
      primary.client_secret_expires_at ??
      nextOauth.client_secret_expires_at ??
      undefined;
    nextOauth.resource_uri =
      primary.resource_uri ??
      nextOauth.resource_uri ??
      config.resource_uri ??
      config.resource ??
      undefined;
    nextOauth.resource =
      primary.resource ??
      nextOauth.resource ??
      config.resource ??
      config.resource_uri ??
      undefined;
    nextOauth.default_scopes =
      primary.default_scopes ??
      nextOauth.default_scopes ??
      config.default_scopes ??
      undefined;
  }

  return {
    ...config,
    clients: deduped,
    oauth: nextOauth,
  };
};

const appRowToApp = (row?: AppRow | null): App | undefined => {
  if (!row) {
    return undefined;
  }
  const config = parseAppConfig(row.config);
  const resourceUri = resourceFromConfig(config) ?? "";
  const defaultScopes = defaultScopesFromConfig(config);
  const mcpServerIds = normalizeStringArray(row.mcp_server_ids);
  const metaInfo = parseAppMetaInfo(row.app_meta_info);
  return {
    id: row.id,
    uuid: row.id,
    name: row.name,
    resource_uri: resourceUri,
    payment_link: row.payment_link ?? undefined,
    mcp_server_ids: mcpServerIds,
    default_scopes: canonicalizeScopes(defaultScopes).join(" "),
    status: row.status ?? undefined,
    config,
    meta_info: metaInfo,
  };
};

const appConfigClientToClient = (
  clientConfig: AppConfigClient,
  app: App
): Client => {
  const redirectUris = coerceStringArray(clientConfig.redirect_uris);
  const grantTypes = coerceStringArray(clientConfig.grant_types);
  const scopeString =
    (clientConfig.scope && canonicalScopeString(clientConfig.scope)) ||
    (defaultScopesFromConfig(app.config).length > 0
      ? canonicalScopeString(defaultScopesFromConfig(app.config))
      : "") ||
    (app.default_scopes
      ? canonicalScopeString(app.default_scopes)
      : "") ||
    canonicalScopeString(DEFAULT_SCOPE_FALLBACK);

  return {
    client_id: clientConfig.client_id ?? "",
    client_secret: clientConfig.client_secret ?? null,
    client_name: clientConfig.client_name ?? app.name,
    token_endpoint_auth_method:
      clientConfig.token_endpoint_auth_method ?? "none",
    application_type: clientConfig.application_type ?? "web",
    redirect_uris: redirectUris.length > 0 ? redirectUris : [],
    grant_types:
      grantTypes.length > 0
        ? grantTypes
        : ["authorization_code", "refresh_token"],
    scope: scopeString,
    app_uuid: app.id,
    registration_access_token: clientConfig.registration_access_token ?? null,
    registration_client_uri: clientConfig.registration_client_uri ?? null,
    client_id_issued_at: clientConfig.client_id_issued_at ?? 0,
    client_secret_expires_at: clientConfig.client_secret_expires_at ?? 0,
  };
};

const userRowToUser = (row?: AppUserRow | null): User | undefined =>
  row
    ? {
        uuid: row.id,
        email: (row.email ?? "").toLowerCase(),
        password_hash: row.password_hash ?? undefined,
        display_name: row.name ?? undefined,
        app_id: row.app_id ?? undefined,
        auth_provider: row.auth_provider ?? undefined,
        firebase_uid: row.firebase_uid ?? undefined,
        provider_user_id: row.provider_user_id ?? undefined,
      }
    : undefined;

const parseScopes = (scopeString?: string | null): string[] =>
  scopeString
    ? scopeString
        .split(" ")
        .map((scope) => scope.trim())
        .filter(Boolean)
    : [];

const normalizeResource = (value: string): string =>
  value.endsWith("/") && value.length > 1
    ? value.replace(/\/+$/, "")
    : value;

const parseAppMetaInfo = (value: unknown): AppMetaInfo | undefined => {
  if (!value) {
    return undefined;
  }
  let resolved: unknown = value;
  if (typeof value === "string") {
    try {
      resolved = JSON.parse(value);
    } catch (error) {
      console.warn("Failed to parse app_meta_info JSON", error);
      return undefined;
    }
  }
  if (typeof resolved !== "object" || resolved === null) {
    return undefined;
  }
  try {
    return JSON.parse(JSON.stringify(resolved)) as AppMetaInfo;
  } catch (error) {
    console.warn("Failed to sanitize app_meta_info payload", error);
    return undefined;
  }
};

const fetchAllApps = async (): Promise<App[]> => {
  const { data, error } = await supabase
    .from("apps")
    .select(
      "id,name,config,status,payment_link,mcp_server_ids,app_meta_info,created_at,updated_at"
    );
  if (error) {
    throw new Error(`Failed to fetch apps: ${error.message}`);
  }
  return (data ?? [])
    .map((row) => appRowToApp(row as AppRow))
    .filter((app): app is App => Boolean(app));
};

const locateAppByClientId = async (
  clientId: string
): Promise<{ app: App; clientConfig: AppConfigClient }> => {
  const apps = await fetchAllApps();
  for (const app of apps) {
    const clients = appConfigClients(app.config);
    const match = clients.find(
      (client) => client.client_id === clientId
    );
    if (match) {
      return { app, clientConfig: match };
    }
  }
  throw new Error(`Client ${clientId} not found in any app config.`);
};

const updateAppConfig = async (appId: string, config: AppConfig) => {
  const { error } = await supabase
    .from("apps")
    .update({
      config: serializeAppConfig(config),
      updated_at: new Date().toISOString(),
    })
    .eq("id", appId);
  if (error) {
    throw new Error(`Failed to update app config: ${error.message}`);
  }
};

export const findUserByEmail = async (
  email: string,
  options?: { appId?: string | null; fallbackToAny?: boolean }
): Promise<User | undefined> => {
  const normalizedEmail = email.trim().toLowerCase();
  const fallbackToAny = options?.fallbackToAny ?? true;

  const queryByApp = async (
    appId: string | null
  ): Promise<User | undefined> => {
    let query = supabase
      .from("app_users")
      .select("*")
      .ilike("email", normalizedEmail)
      .limit(1);
    if (appId === null) {
      query = query.is("app_id", null);
    } else {
      query = query.eq("app_id", appId);
    }
    const { data, error } = await query;
    if (error) {
      throw new Error(`Failed to fetch user by email: ${error.message}`);
    }
    const record = Array.isArray(data) ? (data[0] as AppUserRow | undefined) : undefined;
    return userRowToUser(record ?? undefined);
  };

  if (options && Object.prototype.hasOwnProperty.call(options, "appId")) {
    const appScoped = await queryByApp(options.appId ?? null);
    if (appScoped || !fallbackToAny) {
      return appScoped;
    }
  }

  const { data, error } = await supabase
    .from("app_users")
    .select("*")
    .ilike("email", normalizedEmail)
    .limit(1);
  if (error) {
    throw new Error(`Failed to fetch user by email: ${error.message}`);
  }
  const record = Array.isArray(data) ? (data[0] as AppUserRow | undefined) : undefined;
  return userRowToUser(record ?? undefined);
};

export const findUserByUuid = async (
  uuid: string
): Promise<User | undefined> => {
  const { data, error } = await supabase
    .from("app_users")
    .select("*")
    .eq("id", uuid)
    .maybeSingle();
  if (error) {
    throw new Error(`Failed to fetch user by id: ${error.message}`);
  }
  return userRowToUser((data as AppUserRow | null) ?? undefined);
};

export const createUser = async (
  email: string,
  passwordHash: string,
  displayName?: string,
  options?: {
    appId?: string;
    authProvider?: string;
    firebaseUid?: string;
    providerUserId?: string;
  }
): Promise<User> => {
  const id = randomUUID();
  const now = new Date().toISOString();
  const payload = {
    id,
    email: email.toLowerCase(),
    password_hash: passwordHash,
    name: displayName ?? null,
    app_id: options?.appId ?? null,
    auth_provider: options?.authProvider ?? null,
    firebase_uid: options?.firebaseUid ?? null,
    provider_user_id: options?.providerUserId ?? null,
    created_at: now,
    updated_at: now,
  };
  const { data, error } = await supabase
    .from("app_users")
    .insert(payload)
    .select("*")
    .single();
  if (error || !data) {
    throw new Error(`Failed to create user: ${error?.message ?? "unknown"}`);
  }
  return userRowToUser(data as AppUserRow)!;
};

export const findAppByResource = async (
  resourceUri: string
): Promise<App | undefined> => {
  const target = normalizeResource(resourceUri);
  const apps = await fetchAllApps();
  return apps.find((app) => {
    if (app.resource_uri && normalizeResource(app.resource_uri) === target) {
      return true;
    }
    return app.mcp_server_ids.some(
      (serverId) => normalizeResource(serverId) === target
    );
  });
};

export const findAppByUuid = async (uuid: string): Promise<App | undefined> => {
  const { data, error } = await supabase
    .from("apps")
    .select(
      "id,name,config,status,payment_link,mcp_server_ids,app_meta_info,created_at,updated_at"
    )
    .eq("id", uuid)
    .maybeSingle();
  if (error) {
    throw new Error(`Failed to fetch app by id: ${error.message}`);
  }
  return appRowToApp((data as AppRow | null) ?? undefined);
};

export const listApps = async (): Promise<App[]> => {
  return fetchAllApps();
};

const ACTIVE_PAYMENT_STATUSES = new Set([
  "active",
  "paid",
  "succeeded",
  "completed",
  "trialing",
  "trial",
  "valid",
]);

export const userHasActivePayment = async (
  appId: string,
  userUuid: string
): Promise<boolean> => {
  const { data, error } = await supabase
    .from("app_user_payments")
    .select("id,app_id,user_uuid,status,expires_at,updated_at")
    .eq("app_id", appId)
    .eq("user_uuid", userUuid)
    .order("updated_at", { ascending: false })
    .limit(10);
  if (error) {
    throw new Error(`Failed to check payment status: ${error.message}`);
  }
  const now = Date.now();
  return (data as AppUserPaymentRow[] | null | undefined)?.some((row) => {
    if (!row) {
      return false;
    }
    const status = (row.status ?? "").trim().toLowerCase();
    if (status && !ACTIVE_PAYMENT_STATUSES.has(status)) {
      return false;
    }
    if (row.expires_at) {
      const expires = new Date(row.expires_at);
      if (!Number.isNaN(expires.getTime()) && expires.getTime() < now) {
        return false;
      }
    }
    return true;
  }) ?? false;
};

export const getAppScopes = (app: App): string[] => {
  const configScopes = defaultScopesFromConfig(app.config);
  if (configScopes.length > 0) {
    return configScopes;
  }
  const storedScopes = parseScopes(app.default_scopes);
  if (storedScopes.length > 0) {
    return canonicalizeScopes(storedScopes);
  }
  const clientScopes = appConfigClients(app.config)
    .map((client) => normalizeScopeInput(client.scope))
    .find((scopes) => scopes.length > 0);
  if (clientScopes && clientScopes.length > 0) {
    return canonicalizeScopes(clientScopes);
  }
  return canonicalizeScopes([...DEFAULT_SCOPE_FALLBACK]);
};

export const getAllSupportedScopes = async (): Promise<string[]> => {
  const scopeSet = new Set<string>();
  const apps = await listApps();
  apps.forEach((app) => {
    getAppScopes(app).forEach((scope) => scopeSet.add(scope));
  });
  if (scopeSet.size === 0) {
    DEFAULT_SCOPE_FALLBACK.forEach((scope) => scopeSet.add(scope));
  }
  return canonicalizeScopes(Array.from(scopeSet));
};

export const findClientById = async (
  clientId: string
): Promise<Client | undefined> => {
  try {
    const { app, clientConfig } = await locateAppByClientId(clientId);
    return appConfigClientToClient(clientConfig, app);
  } catch {
    return undefined;
  }
};

export const findClientByRegistrationAccessToken = async (
  token: string
): Promise<Client | undefined> => {
  const apps = await fetchAllApps();
  for (const app of apps) {
    const clients = appConfigClients(app.config);
    const match = clients.find(
      (client) => client.registration_access_token === token
    );
    if (match) {
      return appConfigClientToClient(match, app);
    }
  }
  return undefined;
};

export const createClient = async (
  client: Omit<
    Client,
    | "client_id"
    | "client_secret"
    | "client_id_issued_at"
    | "client_secret_expires_at"
    | "registration_access_token"
    | "registration_client_uri"
  >
): Promise<Client> => {
  const app = await findAppByUuid(client.app_uuid);
  if (!app) {
    throw new Error(`App ${client.app_uuid} not found.`);
  }

  const configClone: AppConfig = JSON.parse(
    JSON.stringify(app.config ?? {})
  );
  const clients = appConfigClients(configClone);
  const staticClients = clients.filter((existing) => !isDynamicClient(existing));

  const clientId = randomUUID();
  const issuedAt = Math.floor(Date.now() / 1000);
  const clientSecret =
    client.token_endpoint_auth_method === "none"
      ? null
      : crypto.randomBytes(32).toString("hex");
  const secretExpiresAt =
    client.token_endpoint_auth_method === "none"
      ? 0
      : issuedAt + CONFIG.refreshTokenTtlSeconds;
  const registrationAccessToken = crypto.randomBytes(32).toString("hex");
  const registrationClientUri = `${CONFIG.issuer}/oauth/client/${clientId}`;

  const newClientConfig: AppConfigClient = {
    client_id: clientId,
    client_secret: clientSecret,
    client_name: client.client_name ?? app.name,
    application_type: client.application_type,
    redirect_uris: client.redirect_uris,
    grant_types: client.grant_types,
    scope:
      (client.scope && canonicalScopeString(client.scope)) ||
      canonicalScopeString(getAppScopes(app)),
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    registration_access_token: registrationAccessToken,
    registration_client_uri: registrationClientUri,
    client_id_issued_at: issuedAt,
    client_secret_expires_at: secretExpiresAt,
  };

  // Ensure clients are tracked under config.clients for persistence.
  const nextConfig = withClientsInConfig(configClone, [
    ...staticClients,
    newClientConfig,
  ]);

  await updateAppConfig(app.id, nextConfig);

  const updatedApp = await findAppByUuid(app.id);
  if (!updatedApp) {
    throw new Error("App disappeared after updating client configuration.");
  }

  return appConfigClientToClient(newClientConfig, updatedApp);
};

export const updateClientScopes = async (
  clientId: string,
  scope: string
): Promise<void> => {
  const { app } = await locateAppByClientId(clientId);
  const configClone: AppConfig = JSON.parse(
    JSON.stringify(app.config ?? {})
  );
  const clients = appConfigClients(configClone);
  let updated = false;
  const nextClients = clients.map((clientConfig) => {
    if (clientConfig.client_id === clientId) {
      updated = true;
      return {
        ...clientConfig,
        scope: canonicalScopeString(scope),
      };
    }
    return clientConfig;
  });

  if (!updated) {
    throw new Error(`Client ${clientId} not found for scope update.`);
  }

  const nextConfig = withClientsInConfig(configClone, nextClients);
  await updateAppConfig(app.id, nextConfig);
};

export const persistAuthorizationCode = async (
  code: AuthorizationCode
): Promise<void> => {
  const { app } = await locateAppByClientId(code.client_id);
  const configClone: AppConfig = JSON.parse(
    JSON.stringify(app.config ?? {})
  );
  const existing = Array.isArray(configClone.authorization_codes)
    ? configClone.authorization_codes.filter(
        (record): record is AppAuthorizationCodeRecord =>
          record &&
          typeof record === "object" &&
          typeof (record as AppAuthorizationCodeRecord).code === "string"
      )
    : [];
  const nextRecords = existing.filter(
    (record) => record.code !== code.code
  );
  nextRecords.push({
    code: code.code,
    user_uuid: code.user_uuid,
    client_id: code.client_id,
    redirect_uri: code.redirect_uri,
    scope: canonicalScopeString(code.scope),
    code_challenge: code.code_challenge,
    code_challenge_method: code.code_challenge_method,
    resource: code.resource,
    expires_at: code.expires_at,
    consumed: code.consumed,
  });
  configClone.authorization_codes = nextRecords;
  await updateAppConfig(app.id, configClone);
};

export const consumeAuthorizationCode = async (
  codeValue: string
): Promise<AuthorizationCode | undefined> => {
  const apps = await fetchAllApps();
  for (const app of apps) {
    const records = Array.isArray(app.config.authorization_codes)
      ? app.config.authorization_codes.filter(
          (record): record is AppAuthorizationCodeRecord =>
            record &&
            typeof record === "object" &&
            (record as AppAuthorizationCodeRecord).code === codeValue
        )
      : [];
    const match = records.find(
      (record) => record.code === codeValue && record.consumed === 0
    );
    if (!match) {
      continue;
    }
    const updatedRecords = Array.isArray(app.config.authorization_codes)
      ? app.config.authorization_codes.map((record) => {
          if (
            record &&
            typeof record === "object" &&
            (record as AppAuthorizationCodeRecord).code === codeValue
          ) {
            return {
              ...(record as AppAuthorizationCodeRecord),
              consumed: 1,
            };
          }
          return record;
        })
      : [];
    const configClone: AppConfig = JSON.parse(
      JSON.stringify(app.config ?? {})
    );
    configClone.authorization_codes = updatedRecords.filter(
      (record): record is AppAuthorizationCodeRecord =>
        record !== undefined && record !== null
    );
    await updateAppConfig(app.id, configClone);
    return {
      code: match.code,
      user_uuid: match.user_uuid,
      client_id: match.client_id,
      redirect_uri: match.redirect_uri,
      scope: match.scope,
      code_challenge: match.code_challenge,
      code_challenge_method: match
        .code_challenge_method as AuthorizationCode["code_challenge_method"],
      resource: match.resource,
      expires_at: match.expires_at,
      consumed: 1,
    };
  }
  return undefined;
};

export const storeAccessToken = async (token: StoredToken): Promise<void> => {
  const { error } = await supabase.from("app_user_access_tokens").insert({
    token: token.token,
    user_uuid: token.user_uuid,
    client_id: token.client_id,
    scope: token.scope,
    resource: token.resource,
    expires_at: token.expires_at,
  });
  if (error) {
    throw new Error(`Failed to store access token: ${error.message}`);
  }
};

export const storeRefreshToken = async (token: StoredToken): Promise<void> => {
  const { error } = await supabase.from("app_user_refresh_tokens").insert({
    token: token.token,
    user_uuid: token.user_uuid,
    client_id: token.client_id,
    scope: token.scope,
    resource: token.resource,
    expires_at: token.expires_at,
  });
  if (error) {
    throw new Error(`Failed to store refresh token: ${error.message}`);
  }
};

export const findRefreshToken = async (
  token: string
): Promise<StoredToken | undefined> => {
  const { data, error } = await supabase
    .from("app_user_refresh_tokens")
    .select("*")
    .eq("token", token)
    .maybeSingle();
  if (error) {
    throw new Error(`Failed to fetch refresh token: ${error.message}`);
  }
  return data
    ? {
        token: (data as TokenRow).token,
        user_uuid: (data as TokenRow).user_uuid,
        client_id: (data as TokenRow).client_id,
        scope: (data as TokenRow).scope,
        resource: (data as TokenRow).resource,
        expires_at: (data as TokenRow).expires_at,
      }
    : undefined;
};

export const revokeRefreshToken = async (token: string): Promise<void> => {
  const { error } = await supabase
    .from("app_user_refresh_tokens")
    .delete()
    .eq("token", token);
  if (error) {
    throw new Error(`Failed to revoke refresh token: ${error.message}`);
  }
};

export const validateScopes = (
  app: App,
  requestedScopes: string[]
): string[] => {
  const allowed = new Set(getAppScopes(app));
  return requestedScopes.filter((scope) => allowed.has(scope));
};
