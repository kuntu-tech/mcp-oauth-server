import type express from "express";
import { z } from "zod";
import { hashPassword, verifyPassword } from "../utils/password";
import { findUserByEmail, createUser } from "../store";
import { resolveSessionAppId } from "../middleware/session";
import { renderPage } from "../renderers/base";

/**
 * Login page route (redirects to home)
 */
export const getLogin = (req: express.Request, res: express.Response): void => {
  const clientIdParam = req.query.client_id;
  const clientId =
    typeof clientIdParam === "string" && clientIdParam.length > 0
      ? clientIdParam
      : undefined;
  const target = clientId
    ? `/?client_id=${encodeURIComponent(clientId)}`
    : "/";
  res.redirect(target);
};

/**
 * Login POST route
 */
export const postLogin = async (
  req: express.Request,
  res: express.Response
): Promise<void> => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res
      .status(400)
      .send(renderPage("Login failed", `<p class="danger">Invalid credentials.</p>`));
    return;
  }
  const { email, password } = parsed.data;
  const sessionAppId = await resolveSessionAppId(req);
  if (!sessionAppId) {
    res
      .status(400)
      .send(
        renderPage(
          "Login failed",
          `<p class="danger">Unable to determine the application context for this login. Please start the sign-in flow from the app's authorization link.</p>`
        )
      );
    return;
  }
  const user = await findUserByEmail(email.toLowerCase(), {
    appId: sessionAppId,
    fallbackToAny: false,
  });
  if (!user?.password_hash || !verifyPassword(password, user.password_hash)) {
    res
      .status(401)
      .send(renderPage("Login failed", `<p class="danger">Incorrect email or password.</p>`));
    return;
  }
  req.session.userUuid = user.uuid;
  res.redirect("/");
};

/**
 * Register page route (redirects to home)
 */
export const getRegister = (req: express.Request, res: express.Response): void => {
  const clientIdParam = req.query.client_id;
  const clientId =
    typeof clientIdParam === "string" && clientIdParam.length > 0
      ? clientIdParam
      : undefined;
  const target = clientId
    ? `/?client_id=${encodeURIComponent(clientId)}`
    : "/";
  res.redirect(target);
};

/**
 * Register POST route
 */
export const postRegister = async (
  req: express.Request,
  res: express.Response
): Promise<void> => {
  const schema = z.object({
    email: z.string().email(),
    password: z.string().min(12),
    displayName: z.string().optional(),
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    res
      .status(400)
      .send(
        renderPage(
          "Registration failed",
          `<p class="danger">Please provide a valid email and a password of at least 12 characters.</p>`
        )
      );
    return;
  }
  const email = parsed.data.email.toLowerCase();
  const sessionAppId = await resolveSessionAppId(req);
  if (!sessionAppId) {
    res
      .status(400)
      .send(
        renderPage(
          "Registration failed",
          `<p class="danger">Unable to determine the application context for this registration. Please start the sign-up flow from the app's authorization link.</p>`
        )
      );
    return;
  }
  if (
    await findUserByEmail(email, {
      appId: sessionAppId,
      fallbackToAny: false,
    })
  ) {
    res
      .status(409)
      .send(
        renderPage(
          "Registration failed",
          `<p class="danger">This email address is already registered for this app.</p>`
        )
      );
    return;
  }
  const passwordHash = hashPassword(parsed.data.password);
  const user = await createUser(email, passwordHash, parsed.data.displayName, {
    appId: sessionAppId,
    authProvider: "local",
  });
  req.session.userUuid = user.uuid;
  res.redirect("/");
};

/**
 * Logout route
 */
export const getLogout = (req: express.Request, res: express.Response): void => {
  req.session.destroy(() => {
    res.redirect("/");
  });
};

