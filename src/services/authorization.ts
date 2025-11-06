import crypto from "crypto";
import type express from "express";
import type { PendingAuthRequest } from "../types/common";
import { AuthorizationRequestError } from "../types/common";
import { escapeHtml } from "../utils/html";
import { sanitizeForLogging } from "../middleware/logging";
import { persistAuthorizationCode, findClientById, validateScopes, canonicalizeScopes, moveClientToApp } from "../store";
import { findAppByResourceLocal } from "../utils/app";
import { persistSession } from "../middleware/session";
import type { App, Client } from "../store";

export type AuthorizationParams = {
  response_type: "code";
  client_id: string;
  redirect_uri: string;
  scope: string;
  state?: string;
  code_challenge: string;
  code_challenge_method: "S256";
  resource: string;
};

/**
 * Prepares authorization details from request parameters
 */
export const prepareAuthorizationDetails = async (params: AuthorizationParams): Promise<{
  authRequest: PendingAuthRequest;
  client: Client;
  app: App;
}> => {
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

/**
 * Completes authorization request by issuing authorization code
 */
export const completeAuthorizationRequest = async (
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

/**
 * Issues authorization code and redirects, handling payment checks
 */
export const issueCodeAndRedirect = async (
  req: express.Request,
  res: express.Response,
  userUuid: string,
  authRequest: PendingAuthRequest
): Promise<void> => {
  const { ensurePaymentAccess } = await import("./payment");
  const { renderPage } = await import("../renderers/base");
  const { escapeHtml } = await import("../utils/html");
  
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
      await persistSession(req);
      const sessionAuthRequest = req.session.authRequest as
        | PendingAuthRequest
        | undefined;
      const redirectTarget =
        sessionAuthRequest?.client_id && sessionAuthRequest.client_id.length > 0
          ? `/?client_id=${encodeURIComponent(sessionAuthRequest.client_id)}`
          : "/";
      res.redirect(redirectTarget);
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

