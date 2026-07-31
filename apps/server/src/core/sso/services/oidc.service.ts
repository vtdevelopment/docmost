import { BadRequestException, Injectable, Logger } from '@nestjs/common';
import * as client from 'openid-client';
import { AuthProvider, Workspace } from '@docmost/db/types/entity.types';
import { EnvironmentService } from '../../../integrations/environment/environment.service';
import { DomainService } from '../../../integrations/environment/domain.service';
import {
  OIDC_DISCOVERY_CACHE_TTL_MS,
  OIDC_SCOPE,
  SsoProviderType,
} from '../sso.constants';
import { pickEmailClaim } from '../sso.util';

/**
 * The subset of an auth provider needed to talk to the identity provider.
 * Narrower than AuthProvider so a partially-updated provider (whose date
 * columns widen when spread) can be validated before it is persisted.
 */
export type OidcProviderConfig = {
  id: string;
  type: string;
  oidcIssuer?: string | null;
  oidcClientId?: string | null;
  oidcClientSecret?: string | null;
};

export type OidcIdentity = {
  /** Stable per (app registration, user). Stored in auth_accounts. */
  providerUserId: string;
  email: string;
  name: string;
};

type CachedConfiguration = {
  configuration: client.Configuration;
  /** Invalidate when the admin edits the issuer or credentials. */
  signature: string;
  expiresAt: number;
};

@Injectable()
export class OidcService {
  private readonly logger = new Logger(OidcService.name);

  /**
   * In-process cache of discovered configurations. A `Configuration` holds live
   * JWKS state and is not serialisable, so this cannot live in Redis — each
   * replica warms its own, which is fine.
   */
  private readonly configurations = new Map<string, CachedConfiguration>();

  constructor(
    private readonly environmentService: EnvironmentService,
    private readonly domainService: DomainService,
  ) {}

  /**
   * Must be byte-identical to the Callback URL the admin UI displays
   * (buildCallbackUrl in apps/client/src/ee/security/sso.utils.ts) and to the
   * Redirect URI registered at the identity provider — Entra requires an exact
   * string match and returns AADSTS50011 otherwise.
   *
   * Note the client derives its origin from `window.location`, while this
   * derives from APP_URL. They agree in production; in dev they only agree if
   * you browse the server's own port rather than Vite's.
   */
  buildRedirectUri(provider: AuthProvider, workspace: Workspace): string {
    const base = this.domainService.getUrl(workspace?.hostname);
    return `${base}/api/sso/${SsoProviderType.OIDC}/${provider.id}/callback`;
  }

  async discover(
    provider: OidcProviderConfig,
    opts?: { skipCache?: boolean },
  ): Promise<client.Configuration> {
    if (
      !provider.oidcIssuer ||
      !provider.oidcClientId ||
      !provider.oidcClientSecret
    ) {
      throw new BadRequestException('OIDC provider is not fully configured');
    }

    const signature = [
      provider.oidcIssuer,
      provider.oidcClientId,
      provider.oidcClientSecret,
    ].join('|');

    const cached = this.configurations.get(provider.id);
    if (
      !opts?.skipCache &&
      cached &&
      cached.signature === signature &&
      cached.expiresAt > Date.now()
    ) {
      return cached.configuration;
    }

    // discovery() appends /.well-known/openid-configuration itself, preserving
    // any pathname — so an Entra issuer ending in /v2.0 resolves correctly.
    const configuration = await client.discovery(
      new URL(provider.oidcIssuer),
      provider.oidcClientId,
      provider.oidcClientSecret,
    );

    // Only relevant for a local/self-signed IdP during development; production
    // issuers are https and this is a no-op for them.
    if (!provider.oidcIssuer.startsWith('https://')) {
      client.allowInsecureRequests(configuration);
    }

    this.configurations.set(provider.id, {
      configuration,
      signature,
      expiresAt: Date.now() + OIDC_DISCOVERY_CACHE_TTL_MS,
    });

    return configuration;
  }

  /** Drops the cached configuration, e.g. after an admin edit. */
  invalidate(providerId: string): void {
    this.configurations.delete(providerId);
  }

  async buildAuthorizationUrl(
    provider: AuthProvider,
    workspace: Workspace,
    checks: { state: string; nonce: string; codeChallenge: string },
  ): Promise<string> {
    const configuration = await this.discover(provider);

    const url = client.buildAuthorizationUrl(configuration, {
      redirect_uri: this.buildRedirectUri(provider, workspace),
      scope: OIDC_SCOPE,
      response_type: 'code',
      // Must stay `query`: form_post would make the callback a cross-site POST,
      // which the SameSite=Lax state cookie is not sent on.
      response_mode: 'query',
      code_challenge: checks.codeChallenge,
      code_challenge_method: 'S256',
      state: checks.state,
      nonce: checks.nonce,
    });

    return url.href;
  }

  /**
   * Exchanges the authorization code. openid-client validates iss, aud, azp,
   * exp/iat/nbf, nonce, state, at_hash and the JWKS signature internally — none
   * of that is re-implemented here.
   */
  async exchangeCode(
    provider: AuthProvider,
    currentUrl: URL,
    checks: { state: string; nonce: string; codeVerifier: string },
  ): Promise<OidcIdentity> {
    const configuration = await this.discover(provider);

    const tokens = await client.authorizationCodeGrant(
      configuration,
      currentUrl,
      {
        pkceCodeVerifier: checks.codeVerifier,
        expectedNonce: checks.nonce,
        expectedState: checks.state,
        idTokenExpected: true,
      },
    );

    const claims = tokens.claims();
    if (!claims?.sub) {
      throw new Error('ID token is missing the sub claim');
    }

    let email = pickEmailClaim(claims as Record<string, unknown>);
    let name =
      typeof claims['name'] === 'string' ? (claims['name'] as string) : null;

    // Last resort: some tenants only expose the address on the userinfo
    // endpoint. One extra round trip, only when we would otherwise fail.
    if (!email) {
      try {
        const userInfo = await client.fetchUserInfo(
          configuration,
          tokens.access_token,
          claims.sub,
        );
        email = pickEmailClaim(userInfo as unknown as Record<string, unknown>);
        name = name ?? (userInfo.name as string) ?? null;
      } catch (err) {
        this.logger.warn(
          `userinfo lookup failed for provider ${provider.id}: ${(err as Error)?.message}`,
        );
      }
    }

    if (!email) {
      throw new NoEmailClaimError();
    }

    return {
      providerUserId: claims.sub,
      email,
      name: name?.trim() || email.split('@')[0],
    };
  }

  generateChecks(): {
    state: string;
    nonce: string;
    codeVerifier: string;
  } {
    return {
      state: client.randomState(),
      nonce: client.randomNonce(),
      codeVerifier: client.randomPKCECodeVerifier(),
    };
  }

  async calculateCodeChallenge(codeVerifier: string): Promise<string> {
    return client.calculatePKCECodeChallenge(codeVerifier);
  }
}

/**
 * Raised when no usable email address can be resolved from the ID token or the
 * userinfo endpoint. Handled distinctly so the user gets an actionable message.
 */
export class NoEmailClaimError extends Error {
  constructor() {
    super(
      'The identity provider did not return an email address for this account',
    );
    this.name = 'NoEmailClaimError';
  }
}
