import { promises as fs } from "fs";
import { existsSync } from "fs";
import { generateKeyPairSync, randomUUID } from "crypto";
import {
  JWK,
  KeyLike,
  exportJWK,
  importPKCS8,
  importSPKI,
} from "jose";
import { CONFIG } from "./config";

interface StoredKeyMaterial {
  privateKey: string;
  publicKey: string;
  alg: "RS256";
  kid: string;
}

let signingKey: KeyLike;
let verificationKey: KeyLike;
let publicJwk: JWK & { kid: string; use: "sig"; alg: "RS256" };

const writeKeyMaterial = async (payload: StoredKeyMaterial) => {
  await fs.writeFile(CONFIG.jwksPath, JSON.stringify(payload, null, 2), {
    encoding: "utf-8",
  });
};

const createKeyMaterial = async (): Promise<StoredKeyMaterial> => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  const kid = randomUUID();
  const material: StoredKeyMaterial = {
    privateKey,
    publicKey,
    alg: "RS256",
    kid,
  };
  await writeKeyMaterial(material);
  return material;
};

const loadKeyMaterial = async (): Promise<StoredKeyMaterial> => {
  if (!existsSync(CONFIG.jwksPath)) {
    return createKeyMaterial();
  }
  const raw = await fs.readFile(CONFIG.jwksPath, "utf-8");
  try {
    const parsed = JSON.parse(raw) as StoredKeyMaterial;
    if (!parsed.privateKey || !parsed.publicKey || !parsed.kid) {
      throw new Error("Invalid key material");
    }
    return parsed;
  } catch {
    return createKeyMaterial();
  }
};

export const initializeKeys = async (): Promise<void> => {
  const material = await loadKeyMaterial();
  signingKey = await importPKCS8(material.privateKey, material.alg);
  verificationKey = await importSPKI(material.publicKey, material.alg);
  const jwk = await exportJWK(verificationKey);
  publicJwk = {
    ...jwk,
    kid: material.kid,
    use: "sig",
    alg: material.alg,
  };
};

export const getSigningKey = (): KeyLike => {
  if (!signingKey) {
    throw new Error("Signing key not initialized");
  }
  return signingKey;
};

export const getVerificationKey = (): KeyLike => {
  if (!verificationKey) {
    throw new Error("Verification key not initialized");
  }
  return verificationKey;
};

export const getJwks = () => {
  if (!publicJwk) {
    throw new Error("JWKS not initialized");
  }
  return { keys: [publicJwk] };
};

export const getCurrentKeyId = (): string => {
  if (!publicJwk) {
    throw new Error("JWKS not initialized");
  }
  return publicJwk.kid!;
};
