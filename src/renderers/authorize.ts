import { escapeHtml } from "../utils/html";
import type { PendingAuthRequest } from "../types/common";
import { renderPage } from "./base";

/**
 * Renders the authorization page where users can approve or deny access
 */
export const renderAuthorizePage = (
  authRequest: PendingAuthRequest,
  options: {
    clientName: string;
    appName?: string;
    error?: string;
    email?: string;
  }
): string => {
  const scopeList = authRequest.scope
    .map((scope) => `<li><code>${escapeHtml(scope)}</code></li>`)
    .join("");
  const errorBlock = options.error
    ? `<p class="danger">${escapeHtml(options.error)}</p>`
    : "";
  const emailValue = options.email ? ` value="${escapeHtml(options.email)}"` : "";
  const appBlock = options.appName
    ? `<p>App: <strong>${escapeHtml(options.appName)}</strong></p>`
    : "";
  const body = `
    <h1>Authorize ${escapeHtml(options.clientName)}</h1>
    ${appBlock}
    <p>Resource: <code>${escapeHtml(authRequest.resource)}</code></p>
    <div class="scopes">
      <p>The following scopes will be granted:</p>
      <ul>${scopeList}</ul>
    </div>
    ${errorBlock}
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="response_type" value="${escapeHtml(
        authRequest.response_type
      )}" />
      <input type="hidden" name="client_id" value="${escapeHtml(
        authRequest.client_id
      )}" />
      <input type="hidden" name="redirect_uri" value="${escapeHtml(
        authRequest.redirect_uri
      )}" />
      <input type="hidden" name="scope" value="${escapeHtml(
        authRequest.scope.join(" ")
      )}" />
      <input type="hidden" name="code_challenge" value="${escapeHtml(
        authRequest.code_challenge
      )}" />
      <input type="hidden" name="code_challenge_method" value="${escapeHtml(
        authRequest.code_challenge_method
      )}" />
      <input type="hidden" name="resource" value="${escapeHtml(
        authRequest.resource
      )}" />
      ${
        authRequest.state
          ? `<input type="hidden" name="state" value="${escapeHtml(
              authRequest.state
            )}" />`
          : ""
      }
      <label>Email
        <input type="email" name="email" required${emailValue} />
      </label>
      <label>Password
        <input type="password" name="password" required minlength="8" />
      </label>
      <div style="display:flex; gap:0.5rem;">
        <button type="submit" name="decision" value="approve">Sign in and Continue</button>
        <button type="submit" name="decision" value="deny">Cancel</button>
      </div>
    </form>
  `;
  return renderPage("Authorize access", body);
};

