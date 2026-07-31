import {
  Controller,
  Get,
  Inject,
  Logger,
  Param,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { SkipThrottle, Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { FastifyReply, FastifyRequest } from 'fastify';
import {
  AI_CHAT_THROTTLER,
  AUTH_THROTTLER,
} from '../../integrations/throttle/throttler-names';
import { Public } from '../../common/decorators/public.decorator';
import { SkipTransform } from '../../common/decorators/skip-transform.decorator';
import { AuthWorkspace } from '../../common/decorators/auth-workspace.decorator';
import { Workspace } from '@docmost/db/types/entity.types';
import { AuthProviderRepo } from '@docmost/db/repos/auth-provider/auth-provider.repo';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import { SessionService } from '../session/session.service';
import { EnvironmentService } from '../../integrations/environment/environment.service';
import { LicenseCheckService } from '../../integrations/environment/license-check.service';
import { Feature } from '../../common/features';
import { isUserDisabled } from '../../common/helpers';
import { validateAllowedEmail } from '../auth/auth.util';
import {
  AuditEvent,
  AuditResource,
} from '../../common/events/audit-events';
import {
  AUDIT_SERVICE,
  IAuditService,
} from '../../integrations/audit/audit.service';
import { NoEmailClaimError, OidcService } from './services/oidc.service';
import { OidcStateService } from './services/oidc-state.service';
import {
  SignupDisabledError,
  SsoIdentityService,
} from './services/sso-identity.service';
import { OIDC_STATE_COOKIE, SsoError, SsoErrorCode } from './sso.constants';
import { buildLoginErrorRedirect, safeServerRedirectPath, setAuthCookie } from './sso.util';

/**
 * Browser-facing OIDC endpoints.
 *
 * Both routes are top-level navigations, so nothing here may return JSON:
 * every failure redirects to /login?error=<code> and the client maps the code to
 * readable copy. @SkipTransform keeps the global response interceptor from
 * wrapping the redirect in {data, success, status}.
 *
 * The throttle limit is raised above the default auth bucket (10/60s) because
 * that bucket is keyed by IP, and an office behind a single NAT would otherwise
 * be locked out of SSO. These routes carry no guessable credential.
 */
@Public()
@SkipThrottle({ [AI_CHAT_THROTTLER]: true })
@Throttle({ [AUTH_THROTTLER]: { limit: 30, ttl: 60_000 } })
@UseGuards(ThrottlerGuard)
@Controller('sso/oidc')
export class OidcController {
  private readonly logger = new Logger(OidcController.name);

  constructor(
    private readonly oidcService: OidcService,
    private readonly stateService: OidcStateService,
    private readonly ssoIdentityService: SsoIdentityService,
    private readonly authProviderRepo: AuthProviderRepo,
    private readonly userRepo: UserRepo,
    private readonly workspaceRepo: WorkspaceRepo,
    private readonly sessionService: SessionService,
    private readonly environmentService: EnvironmentService,
    private readonly licenseCheckService: LicenseCheckService,
    @Inject(AUDIT_SERVICE) private readonly auditService: IAuditService,
  ) {}

  @SkipTransform()
  @Get(':providerId/login')
  async login(
    @Param('providerId') providerId: string,
    @Query('redirect') redirect: string | undefined,
    @Res() res: FastifyReply,
    @AuthWorkspace() workspace: Workspace,
  ) {
    try {
      const provider = await this.resolveProvider(providerId, workspace);
      if (!provider) {
        return this.fail(res, SsoError.UNAVAILABLE);
      }

      if (
        !provider.oidcIssuer ||
        !provider.oidcClientId ||
        !provider.oidcClientSecret
      ) {
        return this.fail(res, SsoError.MISCONFIGURED);
      }

      const checks = this.oidcService.generateChecks();
      const codeChallenge = await this.oidcService.calculateCodeChallenge(
        checks.codeVerifier,
      );

      // Build the authorization URL first: discovery can fail, and there is no
      // point leaving a state cookie behind for a flow that never started.
      const authorizationUrl = await this.oidcService.buildAuthorizationUrl(
        provider,
        workspace,
        { state: checks.state, nonce: checks.nonce, codeChallenge },
      );

      const stateToken = await this.stateService.sign({
        p: provider.id,
        s: checks.state,
        n: checks.nonce,
        v: checks.codeVerifier,
        r: safeServerRedirectPath(redirect),
      });
      this.stateService.setCookie(res, stateToken);

      return res.redirect(authorizationUrl, 302);
    } catch (err) {
      this.logger.warn(
        `SSO login failed for provider ${providerId}: ${(err as Error)?.message}`,
      );
      return this.fail(res, SsoError.MISCONFIGURED);
    }
  }

  @SkipTransform()
  @Get(':providerId/callback')
  async callback(
    @Param('providerId') providerId: string,
    @Query('error') idpError: string | undefined,
    @Req() req: FastifyRequest,
    @Res() res: FastifyReply,
    @AuthWorkspace() workspace: Workspace,
  ) {
    // Read then immediately invalidate the state cookie, so a captured callback
    // URL cannot be replayed in this browser.
    const stateToken = req.cookies?.[OIDC_STATE_COOKIE];
    this.stateService.clearCookie(res);

    if (!stateToken) {
      return this.fail(res, SsoError.STATE_EXPIRED);
    }

    let payload: Awaited<ReturnType<OidcStateService['verify']>>;
    try {
      payload = await this.stateService.verify(stateToken);
    } catch {
      return this.fail(res, SsoError.STATE_EXPIRED);
    }

    if (payload.p !== providerId) {
      return this.fail(res, SsoError.STATE_MISMATCH);
    }

    // The user declined consent, or the IdP rejected them (e.g. not assigned
    // to the enterprise application).
    if (idpError) {
      this.logger.warn(`IdP returned error for provider ${providerId}`);
      return this.fail(res, SsoError.DENIED);
    }

    try {
      const provider = await this.resolveProvider(providerId, workspace);
      if (!provider) {
        return this.fail(res, SsoError.UNAVAILABLE);
      }

      // openid-client derives the token request's redirect_uri by stripping the
      // query off currentUrl, so this is built from the same helper that
      // produced the authorization request's redirect_uri. Deriving it from
      // req.url instead would break behind a path-rewriting proxy.
      const queryIndex = req.url.indexOf('?');
      const search = queryIndex >= 0 ? req.url.slice(queryIndex) : '';
      const currentUrl = new URL(
        this.oidcService.buildRedirectUri(provider, workspace) + search,
      );

      const identity = await this.oidcService.exchangeCode(
        provider,
        currentUrl,
        {
          state: payload.s,
          nonce: payload.n,
          codeVerifier: payload.v,
        },
      );

      // Honour the workspace's approved email domains, if configured.
      validateAllowedEmail(identity.email, workspace);

      const user = await this.ssoIdentityService.findOrProvision({
        provider,
        workspace,
        identity,
      });

      if (isUserDisabled(user)) {
        return this.fail(res, SsoError.ACCOUNT_DISABLED);
      }

      await this.userRepo.updateLastLogin(user.id, workspace.id);

      // There is no req.user on a public route, so the audit actor must be set
      // explicitly (same as the password-reset path).
      this.auditService.setActorId(user.id);
      this.auditService.log({
        event: AuditEvent.USER_LOGIN,
        resourceType: AuditResource.USER,
        resourceId: user.id,
        metadata: { source: 'sso:oidc', providerId: provider.id },
      });

      const authToken = await this.sessionService.createSessionAndToken(user);
      setAuthCookie(res, authToken, this.environmentService);

      const target = safeServerRedirectPath(payload.r) ?? '/home';
      return res.redirect(target, 302);
    } catch (err) {
      return this.fail(res, this.mapError(err, providerId));
    }
  }

  /**
   * Resolves an enabled OIDC provider, also confirming the feature is on for
   * this workspace so a stale enabled row cannot be used after SSO is turned
   * off instance-wide.
   */
  private async resolveProvider(providerId: string, workspace: Workspace) {
    if (!workspace) return null;

    let { licenseKey } = workspace;
    if (!licenseKey) {
      licenseKey = await this.workspaceRepo.findLicenseKeyById(workspace.id);
    }

    if (
      !this.licenseCheckService.hasFeature(
        licenseKey,
        Feature.SSO_CUSTOM,
        workspace.plan,
      )
    ) {
      return null;
    }

    return this.authProviderRepo.findEnabledOidcById(providerId, workspace.id);
  }

  private mapError(err: unknown, providerId: string): SsoErrorCode {
    if (err instanceof SignupDisabledError) {
      return SsoError.SIGNUP_DISABLED;
    }
    if (err instanceof NoEmailClaimError) {
      return SsoError.NO_EMAIL;
    }
    // validateAllowedEmail throws BadRequestException with this wording.
    const message = (err as Error)?.message ?? '';
    if (message.includes('not approved for this workspace')) {
      return SsoError.EMAIL_DOMAIN;
    }

    // Log the message only — never the URL, code, state, or any token.
    this.logger.error(
      `SSO callback failed for provider ${providerId}: ${message}`,
    );
    return SsoError.FAILED;
  }

  private fail(res: FastifyReply, code: SsoErrorCode) {
    return res.redirect(buildLoginErrorRedirect(code), 302);
  }
}
