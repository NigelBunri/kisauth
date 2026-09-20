// Identity-disambiguation convention for enterprise OIDC identities.
//
// Django's already-shipped `link_identity_server_to_server()` (see
// apps/kis_auth_bridge/views.py + exchange_client.py in the Django repo)
// forwards `provider` through VERBATIM as the literal string "oidc" for
// every enterprise tenant — it does NOT combine it with partner_slug, and
// it does NOT send partner_slug to kis-auth's /internal/v1/identity/link
// at all. That call site is fixed (Django is out of scope for this
// change), so a `provider` column value of "oidc:<partner_slug>" is not
// actually achievable without a Django change.
//
// What Django DOES forward verbatim is `provider_subject` — taken
// directly from the registration-exchange JWT's `provider_subject` claim,
// which kis-auth itself mints (see oidc-enterprise.controller.ts). So the
// tenant-disambiguation lives in THAT claim instead: provider_subject is
// always "<partner_slug>:<raw IdP 'sub' claim>", never the bare sub. This
// keeps (provider, provider_subject) globally unique per tenant even
// though every enterprise identity shares the literal provider "oidc",
// and requires neither a Django change nor a kis-auth schema migration —
// auth_identity.provider_subject is already an unconstrained text column.
export const OIDC_PROVIDER = 'oidc';

export function compositeOidcSubject(partnerSlug: string, sub: string): string {
  return `${partnerSlug}:${sub}`;
}
