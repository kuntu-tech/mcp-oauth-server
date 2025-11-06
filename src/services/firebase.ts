import https from "https";
import type { FirebaseAccountRecord } from "../types/common";
import { CONFIG } from "../config";

/**
 * Decodes JWT payload from Firebase ID token
 */
const decodeJwtPayload = (token: string): Record<string, unknown> | undefined => {
  const [, payload] = token.split(".");
  if (!payload) {
    return undefined;
  }
  try {
    const decoded = Buffer.from(payload, "base64url").toString("utf8");
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch (error) {
    console.warn("Failed to decode Firebase ID token payload", error);
    return undefined;
  }
};

/**
 * Extracts email from token payload
 */
const extractEmailFromTokenPayload = (
  payload: Record<string, unknown> | undefined
): string | undefined => {
  if (!payload) {
    return undefined;
  }
  const pickString = (value: unknown): string | undefined => {
    if (typeof value !== "string") {
      return undefined;
    }
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  };
  const directEmail = pickString(payload.email);
  if (directEmail) {
    return directEmail;
  }
  const firebaseClaim = payload.firebase;
  if (
    firebaseClaim &&
    typeof firebaseClaim === "object" &&
    firebaseClaim !== null
  ) {
    const identities = (firebaseClaim as Record<string, unknown>).identities;
    if (identities && typeof identities === "object" && identities !== null) {
      const identityEntries = identities as Record<string, unknown>;
      const emailIdentities = identityEntries.email;
      if (Array.isArray(emailIdentities)) {
        for (const identity of emailIdentities) {
          const candidate = pickString(identity);
          if (candidate) {
            return candidate;
          }
        }
      }
      for (const value of Object.values(identityEntries)) {
        if (Array.isArray(value)) {
          for (const entry of value) {
            const candidate = pickString(entry);
            if (candidate && candidate.includes("@")) {
              return candidate;
            }
          }
        }
      }
    }
  }
  return undefined;
};

/**
 * Verifies Firebase ID token and returns account information
 */
export const verifyFirebaseIdToken = async (
  idToken: string
): Promise<FirebaseAccountRecord> => {
  if (!CONFIG.firebaseClientConfig?.apiKey) {
    throw new Error("Firebase API Key not configured, cannot verify login.");
  }
  const apiKey = CONFIG.firebaseClientConfig.apiKey;
  const payload = JSON.stringify({ idToken });
  const endpoint = new URL(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${apiKey}`
  );

  const responseBody: string = await new Promise((resolve, reject) => {
    const request = https.request(
      {
        method: "POST",
        hostname: endpoint.hostname,
        path: endpoint.pathname + endpoint.search,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk) => {
          data += chunk;
        });
        res.on("end", () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve(data);
          } else {
            reject(
              new Error(
                `Firebase verification failed (status ${res.statusCode ?? "unknown"}): ${
                  data || "No response content"
                }`
              )
            );
          }
        });
      }
    );
    request.on("error", (error) => reject(error));
    request.write(payload);
    request.end();
  });

  type FirebaseLookupResponse = {
    users?: Array<{
      localId?: string;
      email?: string;
      displayName?: string;
      providerUserInfo?: Array<{
        email?: string;
        displayName?: string;
        providerId?: string;
        rawId?: string;
      }>;
    }>;
  };

  let parsed: FirebaseLookupResponse;
  try {
    parsed = JSON.parse(responseBody) as FirebaseLookupResponse;
  } catch {
    throw new Error("Cannot parse Firebase return data.");
  }

  const tokenPayload = decodeJwtPayload(idToken);
  const user = parsed.users?.[0];
  const providerDisplayName =
    user?.providerUserInfo?.find(
      (info) =>
        typeof info?.displayName === "string" && info.displayName.trim().length > 0
    )?.displayName ?? undefined;
  const providerEmail =
    user?.providerUserInfo?.find(
      (info) => typeof info?.email === "string" && info.email.trim().length > 0
    )?.email ?? undefined;
  const payloadEmail = extractEmailFromTokenPayload(
    tokenPayload as Record<string, unknown> | undefined
  );

  const emailCandidate = (user?.email ?? providerEmail ?? payloadEmail)?.trim();
  if (!emailCandidate) {
    const providerEmails = Array.isArray(user?.providerUserInfo)
      ? user?.providerUserInfo.map((info) => info?.email ?? null)
      : [];
    const logPayload =
      tokenPayload && typeof tokenPayload === "object"
        ? {
            keys: Object.keys(tokenPayload),
            firebaseIdentities:
              typeof (tokenPayload as Record<string, unknown>).firebase === "object" &&
              (tokenPayload as { firebase?: { identities?: unknown } }).firebase?.identities
                ? Object.keys(
                    (tokenPayload as {
                      firebase?: { identities?: Record<string, unknown> };
                    }).firebase!.identities ?? {}
                  )
                : null,
            email: payloadEmail ?? null,
          }
        : null;
    console.warn("Login account missing email details", {
      userEmail: user?.email ?? null,
      providerEmails,
      logPayload,
    });
  }

  const payloadName =
    typeof tokenPayload?.name === "string" && tokenPayload.name.trim().length > 0
      ? tokenPayload.name
      : undefined;
  const displayName =
    (typeof user?.displayName === "string" && user.displayName.trim().length > 0
      ? user.displayName
      : undefined) ??
    providerDisplayName ??
    payloadName;

  return {
    uid: user?.localId ?? "",
    email: emailCandidate,
    displayName,
  };
};

