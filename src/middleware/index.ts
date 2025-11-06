import express from "express";
import session from "express-session";
import morgan from "morgan";
import { CONFIG } from "../config";
import { loggingMiddleware } from "./logging";

/**
 * Sets up basic Express middleware (JSON, URL encoding, etc.)
 */
export const setupBasicMiddleware = (app: express.Application): void => {
  app.use(morgan("combined"));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
};

/**
 * Sets up session middleware
 */
export const setupSessionMiddleware = (app: express.Application): void => {
  app.use(
    session({
      secret: CONFIG.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: CONFIG.baseUrl.startsWith("https://"),
      },
    })
  );
};

/**
 * Sets up logging middleware
 */
export const setupLoggingMiddleware = (app: express.Application): void => {
  app.use(loggingMiddleware());
};

/**
 * Sets up all middleware for the Express application
 */
export const setupMiddleware = (app: express.Application): void => {
  setupBasicMiddleware(app);
  setupSessionMiddleware(app);
  setupLoggingMiddleware(app);
};

