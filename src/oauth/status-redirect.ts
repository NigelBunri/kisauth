import { loadConfig } from '../config/env';

/** Every terminal outcome (success or failure), for every provider, routes
 * through kis-auth's own /status page rather than redirecting straight to
 * the client's redirect_uri — this is what lets the user see a clear
 * "what just happened" message instead of either a raw JSON blob or a
 * silent hand-off to a universal link that may not be verified on their
 * device. The page itself auto-refreshes to clientTarget (already
 * carrying code/error+state) after a couple seconds, with a manual
 * button as the fallback that never depends on JavaScript.
 *
 * Extracted from oauth.controller.ts's original private method so the
 * enterprise OIDC controller shares the exact same behavior instead of a
 * second copy. */
export function statusRedirectUrl(state: string, clientTarget: string): string {
  const url = new URL('/status', loadConfig().baseUrl);
  url.searchParams.set('state', state);
  url.searchParams.set('client_redirect', clientTarget);
  return url.toString();
}
