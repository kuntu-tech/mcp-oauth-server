import type express from "express";
import { getLogin, postLogin, getRegister, postRegister, getLogout } from "./auth";

/**
 * Registers all authentication routes
 */
export const registerAuthRoutes = (app: express.Application): void => {
  app.get("/auth/login", getLogin);
  app.post("/auth/login", postLogin);
  app.get("/auth/register", getRegister);
  app.post("/auth/register", postRegister);
  app.get("/auth/logout", getLogout);
};

