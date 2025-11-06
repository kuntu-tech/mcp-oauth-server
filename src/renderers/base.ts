import type { RenderOptions } from "../types/common";

/**
 * Base page renderer - creates a simple HTML page with title and body
 */
export const renderPage = (
  title: string,
  body: string,
  options?: RenderOptions
): string => `
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>${title}</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 2rem; line-height: 1.5; }
      form { max-width: 420px; margin-top: 1.5rem; display: flex; flex-direction: column; gap: 0.75rem; }
      label { display: flex; flex-direction: column; font-weight: 600; }
      input, select { padding: 0.5rem; font-size: 1rem; }
      button { padding: 0.65rem 1rem; font-size: 1rem; font-weight: 600; cursor: pointer; }
      .danger { color: #c0392b; }
      .scopes { margin: 1rem 0; padding: 1rem; background: #f6f8fa; border-radius: 0.5rem; }
      .panel { margin-top: 1.5rem; padding: 1.5rem; background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 0.75rem; }
      .panel + .panel { margin-top: 1rem; }
      .badges { display: flex; flex-wrap: wrap; gap: 0.5rem; margin: 0.5rem 0 0; padding: 0; list-style: none; }
      .badge { display: inline-flex; align-items: center; padding: 0.25rem 0.75rem; background: #eef2ff; color: #1f2937; border-radius: 999px; font-size: 0.875rem; }
      .feedback { margin-top: 0.75rem; font-weight: 600; }
      .feedback.success { color: #2ecc71; }
      .feedback.error { color: #c0392b; }
      nav { margin-bottom: 1.5rem; }
      nav a { margin-right: 0.5rem; }
    </style>
  </head>
  <body>
    <nav>
      <a href="/">Home</a>
    </nav>
    ${body}
    ${options?.scripts ?? ""}
  </body>
</html>
`;

