import { z } from "zod";

/**
 * OAuth authorization query schema
 */
export const authorizationQuerySchema = z.object({
  response_type: z.literal("code"),
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  scope: z.string().min(1),
  state: z.string().optional(),
  code_challenge: z.string().min(43),
  code_challenge_method: z.literal("S256"),
  resource: z.string().url(),
});

/**
 * Authorization POST schema
 */
export const authorizePostSchema = authorizationQuerySchema.extend({
  email: z.string().email().optional(),
  password: z.string().min(8).optional(),
  decision: z.enum(["approve", "deny"]).optional(),
});

/**
 * Firebase session request schema
 */
export const firebaseSessionRequestSchema = z.object({
  idToken: z.string().min(1, "idToken cannot be empty"),
  resume: authorizationQuerySchema.optional(),
  email: z.string().email().optional(),
});

/**
 * OAuth client registration schema
 */
export const registrationSchema = z.object({
  redirect_uris: z.array(z.string().url()).min(1),
  client_name: z.string().optional(),
  application_type: z.enum(["web", "native"]).default("web"),
  grant_types: z
    .array(z.enum(["authorization_code", "refresh_token"]))
    .default(["authorization_code", "refresh_token"]),
  response_types: z.array(z.string()).optional(),
  token_endpoint_auth_method: z
    .enum(["none", "client_secret_post"])
    .default("none"),
  scope: z.string().optional(),
  resource: z.string().url().optional(),
});

/**
 * Token request schema
 */
export const tokenRequestSchema = z.discriminatedUnion("grant_type", [
  z.object({
    grant_type: z.literal("authorization_code"),
    code: z.string(),
    redirect_uri: z.string().url(),
    client_id: z.string(),
    code_verifier: z.string(),
    resource: z.string().url().optional(),
    client_secret: z.string().optional(),
  }),
  z.object({
    grant_type: z.literal("refresh_token"),
    refresh_token: z.string(),
    client_id: z.string(),
    client_secret: z.string().optional(),
  }),
]);

/**
 * Preview token request schema
 */
export const previewTokenRequestSchema = z
  .object({
    client_id: z.string().min(1, "client_id is required"),
    user_uuid: z.string().uuid().optional(),
    email: z.string().email().optional(),
    sub: z.string().min(1).optional(),
    resource: z.string().url().optional(),
  })
  .superRefine((value, ctx) => {
    if (!value.user_uuid && !value.email && !value.sub) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Provide user_uuid, email, or sub to populate the token subject.",
        path: ["user_uuid"],
      });
    }
  });

