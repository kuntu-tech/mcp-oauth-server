import "express-session";

declare module "express-session" {
  interface SessionData {
    userUuid?: string;
    authRequest?: {
      client_id: string;
      redirect_uri: string;
      scope: string[];
      state?: string;
      code_challenge: string;
      code_challenge_method: "S256";
      resource: string;
      response_type: "code";
    };
  }
}
