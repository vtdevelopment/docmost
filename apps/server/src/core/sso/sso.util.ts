import { FastifyReply } from 'fastify';
import { EnvironmentService } from '../../integrations/environment/environment.service';
import { SsoErrorCode } from './sso.constants';

/**
 * Server-side port of `safeRedirectPath` from apps/client/src/lib/app-route.ts.
 *
 * The client already filters the `?redirect=` param, but that is irrelevant to
 * us: an attacker crafts the /api/sso/... URL directly and never runs client
 * code. Only same-origin relative paths are allowed through.
 */
export function safeServerRedirectPath(input: unknown): string | null {
  if (typeof input !== 'string') return null;
  if (input.length === 0 || input.length > 2048) return null;
  // Reject whitespace, backslash, and any Unicode "Other" category char
  // (ASCII controls, zero-width space, BOM, bidi marks, etc).
  if (/[\s\\]|\p{C}/u.test(input)) return null;
  if (!input.startsWith('/') || input.startsWith('//')) return null;
  if (input.toLowerCase().includes('://')) return null;
  if (/^\/[a-z][a-z0-9+\-.]*:/i.test(input)) return null;

  // Resolve against a placeholder origin to normalise traversal (`/a/../b`)
  // and confirm nothing escaped to another host.
  const placeholder = 'https://placeholder.invalid';
  try {
    const resolved = new URL(input, placeholder);
    if (resolved.origin !== placeholder) return null;
    return resolved.pathname + resolved.search + resolved.hash;
  } catch {
    return null;
  }
}

/**
 * Relative redirect target for a failed SSO browser flow. Relative so it works
 * identically behind a reverse proxy and in dev, where the SPA and the API may
 * not share an origin.
 */
export function buildLoginErrorRedirect(code: SsoErrorCode): string {
  return `/login?error=${encodeURIComponent(code)}`;
}

/**
 * Issues the session cookie for an SSO login.
 *
 * Keep in sync with AuthController.setAuthCookie
 * (apps/server/src/core/auth/auth.controller.ts) — the options are entirely
 * EnvironmentService-derived, so they only drift if that method changes.
 */
export function setAuthCookie(
  res: FastifyReply,
  token: string,
  environmentService: EnvironmentService,
): void {
  res.setCookie('authToken', token, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    expires: environmentService.getCookieExpiresIn(),
    secure: environmentService.isHttps(),
  });
}

/**
 * Entra frequently omits the `email` claim even when the `email` scope is
 * granted — it is only emitted when the user has a resolvable mail attribute or
 * the optional `email` claim has been added under Token configuration. Cloud
 * only accounts without an Exchange licence commonly have no mail attribute at
 * all, so we fall back to the UPN.
 *
 * `preferred_username` is the UPN for Entra and is normally an address, but that
 * is not guaranteed, hence the `@` check.
 */
export function pickEmailClaim(
  claims: Record<string, unknown>,
): string | null {
  const candidates = [
    claims['email'],
    claims['preferred_username'],
    claims['upn'],
  ];

  for (const candidate of candidates) {
    if (typeof candidate !== 'string') continue;
    const normalized = candidate.trim().toLowerCase();
    if (normalized.includes('@')) return normalized;
  }

  return null;
}
