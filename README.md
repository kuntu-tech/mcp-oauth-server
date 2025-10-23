# OpenAI Apps-Compatible Auth Server

This project implements an OAuth 2.1 authorization server that satisfies the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) authorization requirements used by the OpenAI Apps SDK. It provides:

- OAuth 2.1 Authorization Code + PKCE flow
- OAuth 2.0 Dynamic Client Registration (`/oauth/register`)
- RFC 9728 protected resource metadata (`/.well-known/oauth-protected-resource`)
- RFC 8414 / OIDC discovery document (`/.well-known/openid-configuration`)
- JWKS endpoint for token verification (`/oauth/jwks`)
- Shared user registry with email uniqueness across all apps
- Access + refresh tokens (JWT access tokens signed with RS256)
- Minimal user portal (login, registration, consent)

Tokens embed `sub` and `email`, allowing you to keep a unified identity across multiple published Apps while restricting access per resource (`aud`) and scope.

---

## Stack

- Node.js + TypeScript
- Express + express-session
- SQLite (via `better-sqlite3`)
- JOSE for JWT/JWKS
- Zod for request validation

---

## Getting Started

1. **Install dependencies**

   ```bash
   npm install
   ```

   > Building `better-sqlite3` can take a few minutes the first time because it compiles native bindings. Feel free to swap it for a different persistence layer if desired.

2. **Copy configuration**

   ```bash
   cp .env.example .env
   ```

   Update values for your environment. The defaults assume the auth server is accessible at `http://localhost:4000` and your MCP resource server is `https://example.com/mcp`.

3. **Run in development**

   ```bash
   npm run dev
   ```

   The server starts on port `4000` (configurable via `PORT`).

4. **Build for production**

   ```bash
   npm run build
   npm start
   ```

---

## Key Endpoints

| Endpoint | Description |
| --- | --- |
| `/.well-known/oauth-protected-resource` | RFC 9728 protected resource metadata pointing to this authorization server. |
| `/.well-known/openid-configuration` | RFC 8414 (OIDC) discovery document. |
| `/oauth/jwks` | JWKS set for RS256 access/id-token verification. |
| `/oauth/register` | Dynamic client registration (POST). |
| `/oauth/authorize` | Authorization code + PKCE entry point (GET). |
| `/oauth/token` | Token endpoint (authorization_code + refresh_token). |
| `/oauth/userinfo` | Basic profile email lookup for authenticated tokens. |
| `/mcp/ping` | Example protected MCP tool endpoint guarded by OAuth. |

---

## Multi-App Identity Strategy

- Users register once; email addresses are unique across every app you publish.
- Each app is represented by a canonical `resource` URI (e.g., `https://your-domain.com/mcp/sales`).
- Dynamic client registrations can specify the associated `resource`. Tokens are minted with `aud` set to that resource so you can differentiate app-level entitlements while keeping a shared `sub`.
- Access tokens carry `scope`, `email`, `azp` (authorized party / client id), and standard OIDC claims. You can enrich them with additional claims to propagate purchase tiers or org membership.

---

## Developing Your Apps

1. Host your MCP server(s) behind OAuth middleware that validates the JWT access tokens returned by this auth server.
2. Ensure each MCP server exposes `/.well-known/oauth-protected-resource` pointing to *this* auth server (you can proxy the controller in front of your resource server or serve the JSON from here).
3. In each OpenAI App, configure the resource URL and required scopes by using the Apps SDK (e.g., `AuthSettings` in FastMCP). Once ChatGPT connects, it will:
   - Retrieve protected-resource metadata
   - Dynamically register a client
   - Launch the authorization flow for the user
   - Exchange tokens and call your tools with `Authorization: Bearer …`

---

## Customizing

- **Database**: swap `better-sqlite3` for Postgres or another provider by changing `src/db.ts` + `src/store.ts`.
- **Tokens**: adjust scopes, TTLs, or claims in `src/config.ts` and `src/tokens.ts`.
- **Consent UX**: update the HTML templates in `src/index.ts` to match your branding and add purchase/upgrade prompts.
- **Admin tooling**: extend client registration with an authenticated dashboard or CLI to issue long-lived confidential clients (e.g., for service-to-service connectors).

---

## Security Notes

- Replace the dev `SESSION_SECRET` and store sessions in a durable backend (Redis, database) in production.
- Rotate signing keys by replacing `data/jwks.json`; clients will pick up the new `kid` through the JWKS endpoint.
- Enforce HTTPS in production and configure reverse proxies (e.g., Nginx) to terminate TLS.
- Consider multi-factor authentication and rate limiting for the login endpoints.

---

## Testing Ideas

- Use a tool like [KeyCloak](https://www.keycloak.org/) or your own resource server to validate tokens against the JWKS endpoint.
- Create integration tests that walk the full PKCE flow using headless browsers (Playwright) to simulate the ChatGPT OAuth prompts.
- Add unit tests around `src/store.ts` to verify token/code lifecycle rules (e.g., no code reuse, refresh revocation).

---

## License

MIT
