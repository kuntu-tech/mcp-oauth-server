import type { App } from "../store";
import { CONFIG } from "../config";
import { listApps } from "../store";
import { normalizeResourceValue } from "./string";

/**
 * Checks if an app matches the given resource URI
 */
export const appMatchesResource = (app: App, resource: string): boolean => {
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

/**
 * Selects the default app from a list of apps based on configuration
 */
export const selectDefaultApp = (apps: App[]): App | undefined => {
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

/**
 * Finds an app by resource URI
 */
export const findAppByResourceLocal = async (
  resource: string
): Promise<App | undefined> => {
  const apps = await listApps();
  return apps.find((app) => appMatchesResource(app, resource));
};

