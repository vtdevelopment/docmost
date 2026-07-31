import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { FastifyReply } from 'fastify';
import { EnvironmentService } from '../../../integrations/environment/environment.service';
import {
  OIDC_STATE_COOKIE,
  OIDC_STATE_COOKIE_PATH,
  OIDC_STATE_JWT_ISSUER,
  OIDC_STATE_TTL_SECONDS,
} from '../sso.constants';

export type OidcStatePayload = {
  /** providerId */
  p: string;
  /** state */
  s: string;
  /** nonce */
  n: string;
  /** PKCE code_verifier */
  v: string;
  /** validated post-login redirect path, or null */
  r: string | null;
};

/**
 * Carries the OIDC flow secrets across the redirect to the identity provider.
 *
 * A signed cookie is used rather than server-side (Redis) storage because it
 * binds the flow to the browser that started it — which is the entire point of
 * `state`. With server-side state an attacker can begin a flow in their own
 * browser and hand the victim the resulting callback URL; the server would find
 * the state valid and sign the victim's browser in as the attacker. That is
 * login CSRF, and only a browser-bound secret prevents it.
 *
 * Single use is enforced practically rather than intrinsically: the cookie is
 * cleared the moment the callback is handled, the token expires in 10 minutes,
 * and the identity provider invalidates the authorization code on first
 * redemption.
 */
@Injectable()
export class OidcStateService {
  constructor(
    private readonly jwtService: JwtService,
    private readonly environmentService: EnvironmentService,
  ) {}

  async sign(payload: OidcStatePayload): Promise<string> {
    return this.jwtService.signAsync(payload);
  }

  async verify(token: string): Promise<OidcStatePayload> {
    return this.jwtService.verifyAsync<OidcStatePayload>(token, {
      secret: this.environmentService.getAppSecret(),
      issuer: OIDC_STATE_JWT_ISSUER,
    });
  }

  setCookie(res: FastifyReply, token: string): void {
    res.setCookie(OIDC_STATE_COOKIE, token, {
      httpOnly: true,
      // MUST be 'lax'. The identity provider redirects back with a cross-site
      // top-level GET; 'strict' would drop the cookie and every login would
      // fail as an expired state.
      sameSite: 'lax',
      secure: this.environmentService.isHttps(),
      path: OIDC_STATE_COOKIE_PATH,
      maxAge: OIDC_STATE_TTL_SECONDS,
    });
  }

  clearCookie(res: FastifyReply): void {
    res.clearCookie(OIDC_STATE_COOKIE, { path: OIDC_STATE_COOKIE_PATH });
  }
}
