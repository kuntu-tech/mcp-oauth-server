import type express from "express";
import type { PendingAuthRequest } from "../types/common";
import { findAppByResourceLocal } from "../utils/app";
import { findClientById } from "../store";

/**
 * Persists session to store
 */
export const persistSession = async (req: express.Request): Promise<void> => {
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

/**
 * Resolves the app ID from the current session
 */
export const resolveSessionAppId = async (
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

