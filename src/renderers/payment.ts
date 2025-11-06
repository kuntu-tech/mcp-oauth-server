import { escapeHtml } from "../utils/html";
import { renderPage } from "./base";

/**
 * Renders the payment required page
 */
export const renderPaymentRequiredPage = (options: {
  appName: string;
  paymentLink: string;
  startedAt?: string;
  priceLabel?: string;
}): string => {
  const priceBlock = options.priceLabel
    ? `<p class="text-sm font-semibold">Price: ${escapeHtml(options.priceLabel)}</p>`
    : "";
  const intro = `
    <h1>Payment required</h1>
    <p>You need an active purchase to use <strong>${escapeHtml(options.appName)}</strong>.</p>
    ${priceBlock}
    <p>Please complete the payment in the new tab. This page will automatically continue once your purchase is confirmed.</p>
    <p><a href="${escapeHtml(options.paymentLink)}" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:0.5rem;padding:0.65rem 1.25rem;background:#2563eb;color:#fff;border-radius:999px;text-decoration:none;font-weight:600;">Open payment page</a></p>
  `;
  const started =
    options.startedAt && options.startedAt.length > 0
      ? `<p class="text-sm">Waiting since ${escapeHtml(options.startedAt)}.</p>`
      : "";
  const script = `
    <script>
      (function () {
        const STATUS_ENDPOINT = "/auth/payment-status";
        const RETRY_DELAY = 5000;
        let stopped = false;
        async function poll() {
          if (stopped) return;
          try {
            const response = await fetch(STATUS_ENDPOINT, {
              credentials: "same-origin",
              headers: {
                "Cache-Control": "no-cache"
              }
            });
            if (!response.ok) {
              throw new Error("Failed to check payment status.");
            }
            const payload = await response.json();
            if (payload?.paid) {
              stopped = true;
              window.location.assign("/auth/payment-resume");
              return;
            }
          } catch (error) {
            console.warn("Payment status check failed", error);
          }
          setTimeout(poll, RETRY_DELAY);
        }
        poll();
      })();
    </script>
  `;
  const body = `
    ${intro}
    ${started}
    <p class="text-sm">You can refresh this page after completing the payment if it doesn't continue automatically.</p>
  `;
  return renderPage("Payment required", body, { scripts: script });
};

