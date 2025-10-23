import crypto from "crypto";
import { SignJWT, jwtVerify, JWTPayload } from "jose";
import { CONFIG } from "./config";
import {
  getCurrentKeyId,
  getSigningKey,
  getVerificationKey,
} from "./keyManager";

export interface AccessTokenClaims extends JWTPayload {
  sub: string;
  aud: string | string[];
  azp: string;
  scope: string;
  email?: string;
}

export const issueAccessToken = async (
  subject: string,
  clientId: string,
  resource: string,
  scope: string,
  email?: string
): Promise<{ token: string; expiresAt: number }> => {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + CONFIG.accessTokenTtlSeconds;
  const signer = getSigningKey();
  const token = await new SignJWT({
    scope,
    azp: clientId,
    email,
  })
    .setIssuedAt(now)
    .setIssuer(CONFIG.issuer)
    .setAudience(resource)
    .setExpirationTime(expiresAt)
    .setSubject(subject)
    .setProtectedHeader({ alg: "RS256", kid: getCurrentKeyId() })
    .sign(signer);

  return { token, expiresAt };
};

export const issueIdToken = async (
  subject: string,
  clientId: string,
  email: string
): Promise<{ token: string; expiresAt: number }> => {
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + CONFIG.accessTokenTtlSeconds;
  const signer = getSigningKey();
  const token = await new SignJWT({
    email,
  })
    .setIssuedAt(now)
    .setIssuer(CONFIG.issuer)
    .setAudience(clientId)
    .setExpirationTime(expiresAt)
    .setSubject(subject)
    .setProtectedHeader({ alg: "RS256", kid: getCurrentKeyId() })
    .sign(signer);
  return { token, expiresAt };
};

export const createRefreshToken = (): { token: string; expiresAt: number } => {
  const token = crypto.randomBytes(48).toString("base64url");
  const expiresAt =
    Math.floor(Date.now() / 1000) + CONFIG.refreshTokenTtlSeconds;
  return { token, expiresAt };
};

export const verifyAccessToken = async (
  token: string
): Promise<AccessTokenClaims> => {
  const result = await jwtVerify(token, getVerificationKey(), {
    issuer: CONFIG.issuer,
  });
  return result.payload as AccessTokenClaims;
};
