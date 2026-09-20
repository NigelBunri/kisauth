// A tiny, dependency-free HTML template — no React/templating engine, just
// a function returning a string, matching "the smallest production-quality
// UI necessary" (Phase 3 §15). No inline <script> anywhere: every dynamic
// behavior (auto-return-to-app) uses <meta http-equiv="refresh">, which
// works with JavaScript disabled and needs no Content-Security-Policy
// script-src relaxation — only style-src gets a narrow, deliberate
// allowance (see main.ts) for the inline <style> block below.

export interface PageOptions {
  title: string;
  heading: string;
  message: string;
  tone: 'success' | 'error' | 'neutral';
  /** If set, the page auto-redirects here after a short delay via <meta
   * refresh>, and also offers it as a manual button — the delay gives the
   * user a moment to actually read what happened before the browser
   * hands off to the app (or, if the app's universal link isn't verified
   * yet, before nothing visibly happens and they're left on this page,
   * which is exactly the state the manual button covers). */
  returnTo?: { url: string; label: string; delaySeconds?: number };
}

const ICONS: Record<PageOptions['tone'], string> = {
  success:
    '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="11" stroke="currentColor" stroke-width="1.5"/><path d="M7.5 12.5l3 3 6-6.5" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/></svg>',
  error:
    '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="11" stroke="currentColor" stroke-width="1.5"/><path d="M12 7v6" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"/><circle cx="12" cy="16.25" r="1" fill="currentColor"/></svg>',
  neutral:
    '<svg width="40" height="40" viewBox="0 0 24 24" fill="none" aria-hidden="true"><circle cx="12" cy="12" r="11" stroke="currentColor" stroke-width="1.5"/><path d="M12 8v4.5l3 2" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"/></svg>',
};

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderPage(opts: PageOptions): string {
  const delay = opts.returnTo?.delaySeconds ?? 2;
  const refreshMeta = opts.returnTo
    ? `<meta http-equiv="refresh" content="${delay};url=${escapeHtml(opts.returnTo.url)}">`
    : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
${refreshMeta}
<title>${escapeHtml(opts.title)} · KIS Auth</title>
<style>
  :root {
    --bg: #12100b;
    --card: #1b1812;
    --border: #33291a;
    --ink: #f4efe4;
    --ink-soft: #b8ac93;
    --gold: #d4af6a;
    --gold-ink: #12100b;
    --success: #7fb88a;
    --error: #e0796f;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 1.5rem;
    background: radial-gradient(circle at 50% 0%, #1d1912 0%, var(--bg) 60%);
    color: var(--ink);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  .card {
    width: 100%;
    max-width: 380px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 2.25rem 1.75rem;
    text-align: center;
  }
  .brand {
    font-size: 0.72rem;
    letter-spacing: 0.16em;
    text-transform: uppercase;
    color: var(--gold);
    font-weight: 600;
    margin-bottom: 1.5rem;
  }
  .icon {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 64px;
    height: 64px;
    border-radius: 50%;
    margin-bottom: 1.25rem;
  }
  .icon.success { background: rgba(127, 184, 138, 0.14); color: var(--success); }
  .icon.error { background: rgba(224, 121, 111, 0.14); color: var(--error); }
  .icon.neutral { background: rgba(212, 175, 106, 0.14); color: var(--gold); }
  h1 {
    font-size: 1.3rem;
    font-weight: 600;
    margin: 0 0 0.6rem;
    text-wrap: balance;
  }
  p.message {
    color: var(--ink-soft);
    font-size: 0.95rem;
    line-height: 1.55;
    margin: 0 0 1.75rem;
  }
  .btn {
    display: inline-block;
    width: 100%;
    padding: 0.85rem 1rem;
    border-radius: 999px;
    background: var(--gold);
    color: var(--gold-ink);
    font-weight: 600;
    font-size: 0.95rem;
    text-decoration: none;
  }
  .btn:focus-visible {
    outline: 2px solid var(--gold);
    outline-offset: 3px;
  }
  .hint {
    margin-top: 1rem;
    font-size: 0.8rem;
    color: var(--ink-soft);
  }
</style>
</head>
<body>
  <main class="card" role="main">
    <div class="brand">KIS Auth</div>
    <div class="icon ${opts.tone}">${ICONS[opts.tone]}</div>
    <h1>${escapeHtml(opts.heading)}</h1>
    <p class="message">${escapeHtml(opts.message)}</p>
    ${
      opts.returnTo
        ? `<a class="btn" href="${escapeHtml(opts.returnTo.url)}">${escapeHtml(opts.returnTo.label)}</a>
    <p class="hint">Returning you to KIS automatically…</p>`
        : ''
    }
  </main>
</body>
</html>`;
}
