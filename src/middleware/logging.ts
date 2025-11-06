import type express from "express";
import type { RouteLogDetails } from "../types/common";

const SENSITIVE_LOG_KEYS = new Set([
  "password",
  "password_hash",
  "clientsecret",
  "client_secret",
  "refresh_token",
  "access_token",
  "id_token",
  "idtoken",
  "registration_access_token",
  "registrationaccesstoken",
  "code",
  "token",
]);

/**
 * Sanitizes data for logging by redacting sensitive information
 */
export const sanitizeForLogging = (input: unknown): unknown => {
  if (input === null || input === undefined) {
    return input;
  }
  if (input instanceof Date) {
    return input.toISOString();
  }
  if (Array.isArray(input)) {
    const limit = 20;
    const sanitized = input.slice(0, limit).map((item) => sanitizeForLogging(item));
    if (input.length > limit) {
      sanitized.push(`...${input.length - limit} more`);
    }
    return sanitized;
  }
  if (typeof input === "object") {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      const normalizedKey = key.toLowerCase();
      if (SENSITIVE_LOG_KEYS.has(normalizedKey)) {
        result[key] = "[REDACTED]";
      } else {
        result[key] = sanitizeForLogging(value);
      }
    }
    return result;
  }
  if (typeof input === "string") {
    return input.length > 160 ? `${input.slice(0, 157)}...` : input;
  }
  return input;
};

/**
 * Logs HTTP events with sanitized details
 */
export const logHttpEvent = (
  method: string,
  url: string,
  phase: "request" | "response" | "error",
  details?: RouteLogDetails
) => {
  const prefix = `[${method} ${url}] ${phase}`;
  const sanitizedDetails = details ? sanitizeForLogging(details) : undefined;
  if (phase === "error") {
    if (sanitizedDetails) {
      console.error(prefix, sanitizedDetails);
    } else {
      console.error(prefix);
    }
  } else if (sanitizedDetails) {
    console.info(prefix, sanitizedDetails);
  } else {
    console.info(prefix);
  }
};

/**
 * Builds request log details from Express request object
 */
export const buildRequestLogDetails = (req: express.Request): RouteLogDetails => {
  const details: RouteLogDetails = {};
  if (req.query && Object.keys(req.query).length > 0) {
    details.query = req.query;
  }
  if (req.body !== undefined) {
    const isEmptyObject =
      typeof req.body === "object" &&
      req.body !== null &&
      !Array.isArray(req.body) &&
      Object.keys(req.body as Record<string, unknown>).length === 0;
    const isEmptyString = typeof req.body === "string" && req.body.trim().length === 0;
    if (!isEmptyObject && !isEmptyString) {
      details.body = req.body;
    }
  }
  if (req.session?.userUuid) {
    details.sessionUser = req.session.userUuid;
  }
  return details;
};

/**
 * Express middleware for logging HTTP requests and responses
 */
export const loggingMiddleware = (): express.RequestHandler => {
  return (req, res, next) => {
    const start = Date.now();
    const { method, originalUrl } = req;
    const requestDetails = buildRequestLogDetails(req);
    if (Object.keys(requestDetails).length > 0) {
      logHttpEvent(method, originalUrl, "request", requestDetails);
    } else {
      logHttpEvent(method, originalUrl, "request");
    }

    res.on("finish", () => {
      const responseDetails: RouteLogDetails = {
        status: res.statusCode,
        durationMs: Date.now() - start,
      };
      if (res.getHeader("x-request-id")) {
        responseDetails.requestId = res.getHeader("x-request-id");
      }
      logHttpEvent(method, originalUrl, "response", responseDetails);
    });

    res.on("error", (error) => {
      const errorDetails: RouteLogDetails = {
        status: res.statusCode,
        error: error instanceof Error ? error.message : error,
      };
      logHttpEvent(method, originalUrl, "error", errorDetails);
    });

    next();
  };
};

