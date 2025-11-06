import type express from "express";
import type { App, AppPaymentModel } from "../store";
import type { PaymentRequirement, PaymentGateDecision, SessionPendingPayment, PendingAuthRequest, PaymentSessionApiResponse } from "../types/common";
import { CONFIG } from "../config";
import { persistSession } from "../middleware/session";
import { findAppByResourceLocal } from "../utils/app";
import { findClientById, findAppByUuid, userHasActivePayment } from "../store";

/**
 * Formats price label from payment model
 */
export const formatPriceLabel = (model?: AppPaymentModel): string | undefined => {
  if (!model) {
    return undefined;
  }
  if (model.model === "subscription") {
    const price =
      typeof model.price === "number"
        ? `$${model.price.toFixed(2)}`
        : model.price !== undefined
        ? String(model.price)
        : undefined;
    const interval =
      typeof model.interval === "string" && model.interval.trim().length > 0
        ? model.interval.trim()
        : undefined;
    if (price && interval) {
      return `${price} / ${interval}`;
    }
    return price ?? undefined;
  }
  return undefined;
};

/**
 * Builds payment requirement from pending payment and app record
 */
export const buildPaymentRequirement = (
  pending: SessionPendingPayment,
  appRecord?: App
): PaymentRequirement => {
  const paymentLink = pending.paymentLink ?? appRecord?.payment_link ?? "";
  if (!paymentLink) {
    throw new Error("Payment link is required but not provided");
  }
  return {
    appName: pending.appName ?? appRecord?.name ?? "this app",
    paymentLink,
    startedAt: pending.startedAt,
    priceLabel: formatPriceLabel(
      (pending.paymentModel as AppPaymentModel | undefined) ?? appRecord?.payment_model
    ),
  };
};

/**
 * Creates a payment session
 */
export const createPaymentSession = async (
  userUuid: string,
  app: App
): Promise<{ url: string; sessionId?: string; raw?: Record<string, unknown> }> => {
  if (!CONFIG.paymentSessionApiUrl) {
    throw new Error("Payment session API URL is not configured.");
  }
  const response = await fetch(CONFIG.paymentSessionApiUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      app_userid: userUuid,
      successUrl: "no-redirect",
      cancelUrl: "no-redirect"
    }),
  });
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new Error(
      `Payment session request failed (${response.status}): ${text || "no response body"}`
    );
  }
  let parsed: PaymentSessionApiResponse;
  try {
    parsed = (await response.json()) as PaymentSessionApiResponse;
  } catch (error) {
    throw new Error("Unable to parse payment session response.");
  }
  if (!parsed?.success || !parsed.data?.url) {
    throw new Error(
      parsed?.message ?? "Payment session API returned an unexpected payload."
    );
  }
  return {
    url: String(parsed.data.url),
    sessionId: parsed.data.sessionId
      ? String(parsed.data.sessionId)
      : undefined,
    raw:
      typeof parsed.data === "object" && parsed.data !== null
        ? (parsed.data as Record<string, unknown>)
        : undefined,
  };
};

/**
 * Ensures user has payment access for the requested resource
 */
export const ensurePaymentAccess = async (
  req: express.Request,
  userUuid: string,
  authRequest: PendingAuthRequest
): Promise<PaymentGateDecision> => {
  let appRecord = await findAppByResourceLocal(authRequest.resource);
  if (!appRecord) {
    try {
      const client = await findClientById(authRequest.client_id);
      if (client) {
        appRecord = await findAppByUuid(client.app_uuid);
      }
    } catch (error) {
      console.warn("Failed to resolve app from client during payment check", error);
    }
  }

  if (!appRecord) {
    return { allowed: true };
  }

  const clearPending = async () => {
    if (req.session.pendingPayment) {
      req.session.pendingPayment = undefined;
      try {
        await persistSession(req);
      } catch (error) {
        console.warn(
          "Failed to persist session while clearing pending payment cache",
          error
        );
      }
    }
  };

  const paymentModel = appRecord.payment_model;
  const existingPending = req.session
    .pendingPayment as SessionPendingPayment | undefined;
  const hasPendingForUser =
    existingPending &&
    existingPending.appId === appRecord.id &&
    existingPending.userUuid === userUuid;

  if (!paymentModel || paymentModel.model === "free") {
    await clearPending();
    return { allowed: true };
  }

  if (paymentModel.model === "subscription") {
    try {
      const hasPayment = await userHasActivePayment(appRecord.id, userUuid);
      if (hasPayment) {
        await clearPending();
        return { allowed: true };
      }
    } catch (error) {
      console.error("Failed to verify payment status", error);
      return {
        allowed: false,
        error: "Unable to verify payment status. Please try again later.",
      };
    }

    if (hasPendingForUser && existingPending?.paymentLink) {
      return {
        allowed: false,
        payment: buildPaymentRequirement(existingPending, appRecord),
      };
    }

    try {
      const sessionInfo = await createPaymentSession(userUuid, appRecord);
      req.session.pendingPayment = {
        appId: appRecord.id,
        paymentLink: sessionInfo.url,
        appName: appRecord.name,
        startedAt: new Date().toISOString(),
        sessionId: sessionInfo.sessionId,
        userUuid,
        paymentModel,
      };
      await persistSession(req);
    } catch (error) {
      console.error("Failed to create payment session", error);
      return {
        allowed: false,
        error: "Unable to initiate payment session. Please try again later.",
      };
    }

    const pendingPayment = req.session
      .pendingPayment as SessionPendingPayment | undefined;
    if (pendingPayment?.paymentLink) {
      return {
        allowed: false,
        payment: buildPaymentRequirement(pendingPayment, appRecord),
      };
    }
    return {
      allowed: false,
      error: "Unable to initiate payment session. Please try again later.",
    };
  }

  const paymentLink = appRecord.payment_link?.trim();
  if (!paymentLink) {
    await clearPending();
    return { allowed: true };
  }

  try {
    const hasPayment = await userHasActivePayment(appRecord.id, userUuid);
    if (hasPayment) {
      await clearPending();
      return { allowed: true };
    }
  } catch (error) {
    console.error("Failed to verify payment status", error);
    return {
      allowed: false,
      error: "Unable to verify payment status. Please try again later.",
    };
  }

  req.session.pendingPayment = {
    appId: appRecord.id,
    paymentLink,
    appName: appRecord.name,
    startedAt: new Date().toISOString(),
    userUuid,
    paymentModel,
  };
  try {
    await persistSession(req);
  } catch (error) {
    console.warn("Failed to persist session after setting pending payment", error);
  }

  const pendingPayment = req.session
    .pendingPayment as SessionPendingPayment | undefined;
  if (pendingPayment?.paymentLink) {
    return {
      allowed: false,
      payment: buildPaymentRequirement(pendingPayment, appRecord),
    };
  }
  return {
    allowed: false,
    error: "Unable to initiate payment session. Please try again later.",
  };
};

