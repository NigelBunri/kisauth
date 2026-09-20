// Documented rate-limit policy for every public/internal kis-auth
// endpoint. One place to see every limit and why it's set where it is,
// rather than magic numbers scattered through controllers.

export const RATE_LIMITS = {
  // Entry point: validates client_id/redirect_uri/purpose and sets a
  // session cookie. Cheap to compute, but still bounded against pure
  // flooding — a legitimate user never needs more than a handful of
  // these per minute even retrying a failed attempt by hand.
  AUTHORIZE: { scope: 'authorize', limit: 30, windowSeconds: 60 },

  // Immediately redirects to Google — same tier as /authorize.
  OAUTH_GOOGLE_START: {
    scope: 'oauth_google_start',
    limit: 30,
    windowSeconds: 60,
  },

  // The highest-value target of the four: this is where a captured
  // state/session could be replayed with guessed `code` values, and
  // every call here spends a real request against Google's token
  // endpoint (real API quota, not just our own compute). Tighter than
  // the other browser-facing endpoints.
  OAUTH_GOOGLE_CALLBACK: {
    scope: 'oauth_google_callback',
    limit: 10,
    windowSeconds: 60,
  },

  // Server-to-server only in the intended deployment, but rate-limited
  // on TWO independent axes since there's no network-level guarantee
  // this port is unreachable from the public internet:
  //   - per client_id: generous, since a legitimate Django deployment
  //     under real recovery-traffic load could legitimately burst: caps
  //     it only to catch a misbehaving or compromised Django instance.
  //   - per IP: catches drive-by abuse from a source that isn't Django
  //     at all, independent of whatever client_id it claims.
  EXCHANGE_PER_CLIENT: {
    scope: 'exchange_client',
    limit: 120,
    windowSeconds: 60,
  },
  EXCHANGE_PER_IP: { scope: 'exchange_ip', limit: 60, windowSeconds: 60 },

  // Same shape as the recovery exchange limits, but tighter — new-account
  // creation is inherently lower-volume than recovery traffic, so a burst
  // here is more suspicious sooner.
  REGISTRATION_EXCHANGE_PER_CLIENT: {
    scope: 'registration_exchange_client',
    limit: 60,
    windowSeconds: 60,
  },
  REGISTRATION_EXCHANGE_PER_IP: {
    scope: 'registration_exchange_ip',
    limit: 30,
    windowSeconds: 60,
  },

  // Enterprise OIDC bridge — same tiers as the equivalent Google routes.
  // /start additionally does a Django round trip (sso-config resolution)
  // and a discovery-document fetch, both cached, so it's no more
  // expensive per-request than Google's fixed-config start once warm.
  OAUTH_ENTERPRISE_START: {
    scope: 'oauth_enterprise_start',
    limit: 30,
    windowSeconds: 60,
  },
  OAUTH_ENTERPRISE_CALLBACK: {
    scope: 'oauth_enterprise_callback',
    limit: 10,
    windowSeconds: 60,
  },
} as const;

export const RATE_LIMIT_ERROR = 'Too many requests. Please try again shortly.';
