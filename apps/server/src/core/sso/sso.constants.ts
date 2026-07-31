import type { StringValue } from 'ms';

export enum SsoProviderType {
  SAML = 'saml',
  OIDC = 'oidc',
  GOOGLE = 'google',
  LDAP = 'ldap',
}

/**
 * Error codes appended to the login redirect when an SSO browser flow fails.
 * The callback is a top-level navigation, so failures cannot surface as JSON.
 *
 * Keep in sync with the SSO_ERRORS whitelist in
 * apps/client/src/ee/components/sso-login.tsx — the client maps these codes to
 * translated copy and ignores anything it does not recognise.
 */
export const SsoError = {
  /** Provider missing, disabled, deleted, or the feature is not enabled. */
  UNAVAILABLE: 'sso_unavailable',
  /** Issuer/client id/secret missing, or OIDC discovery failed. */
  MISCONFIGURED: 'sso_misconfigured',
  /** State cookie absent, expired, or failed signature verification. */
  STATE_EXPIRED: 'sso_state_expired',
  /** State verified but bound to a different provider. */
  STATE_MISMATCH: 'sso_state_mismatch',
  /** The user declined consent at the identity provider. */
  DENIED: 'sso_denied',
  /** No usable email claim on the id token. */
  NO_EMAIL: 'sso_no_email',
  /** Unknown user and the provider has allowSignup off. */
  SIGNUP_DISABLED: 'sso_signup_disabled',
  /** Email domain not in workspaces.email_domains. */
  EMAIL_DOMAIN: 'sso_email_domain',
  /** User is deactivated or soft-deleted. */
  ACCOUNT_DISABLED: 'sso_account_disabled',
  /** Catch-all. */
  FAILED: 'sso_failed',
} as const;

export type SsoErrorCode = (typeof SsoError)[keyof typeof SsoError];

/**
 * Cookie carrying the signed OIDC flow state (PKCE verifier, nonce, state,
 * post-login redirect). Scoped to the callback path so it is never sent
 * anywhere else.
 */
export const OIDC_STATE_COOKIE = 'ssoState';
export const OIDC_STATE_COOKIE_PATH = '/api/sso/oidc';

/** Users have this long to complete the round trip through the IdP. */
export const OIDC_STATE_TTL: StringValue = '10m';
export const OIDC_STATE_TTL_SECONDS = 600;

/** JWT issuer for state tokens, so they cannot be confused with auth tokens. */
export const OIDC_STATE_JWT_ISSUER = 'docmost-sso';

/**
 * How long a discovered OIDC `Configuration` is reused. The object holds live
 * JWKS state and is not serialisable, so this is an in-process cache and each
 * replica warms its own.
 */
export const OIDC_DISCOVERY_CACHE_TTL_MS = 10 * 60 * 1000;

/** Scopes requested from the IdP. `email` is required for account resolution. */
export const OIDC_SCOPE = 'openid profile email';

/**
 * Multi-tenant Entra issuers. Their discovery documents return a *templated*
 * issuer (`.../{tenantid}/v2.0`) which never equals the real id token `iss`, so
 * every login fails validation. They would also admit any Microsoft tenant.
 */
export const MULTI_TENANT_ISSUER_PATTERN =
  /login\.microsoftonline\.com\/(common|organizations|consumers)\//i;
