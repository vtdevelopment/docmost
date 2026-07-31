import {
  BadRequestException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { AuthProviderRepo } from '@docmost/db/repos/auth-provider/auth-provider.repo';
import {
  AuthProvider,
  UpdatableAuthProvider,
  User,
  Workspace,
} from '@docmost/db/types/entity.types';
import { PaginationOptions } from '@docmost/db/pagination/pagination-options';
import { CreateSsoProviderDto } from '../dto/create-sso-provider.dto';
import { UpdateSsoProviderDto } from '../dto/update-sso-provider.dto';
import {
  AuditEvent,
  AuditResource,
} from '../../../common/events/audit-events';
import {
  AUDIT_SERVICE,
  IAuditService,
} from '../../../integrations/audit/audit.service';
import { diffAuditTrackedFields } from '../../../common/helpers';
import { MULTI_TENANT_ISSUER_PATTERN, SsoProviderType } from '../sso.constants';
import { OidcProviderConfig, OidcService } from './oidc.service';

/** Fields safe to record in an audit diff. Never include the client secret. */
const AUDIT_TRACKED_FIELDS = [
  'name',
  'oidcIssuer',
  'oidcClientId',
  'isEnabled',
  'allowSignup',
  'groupSync',
] as const;

@Injectable()
export class SsoService {
  private readonly logger = new Logger(SsoService.name);

  constructor(
    private readonly authProviderRepo: AuthProviderRepo,
    private readonly oidcService: OidcService,
    @Inject(AUDIT_SERVICE) private readonly auditService: IAuditService,
  ) {}

  async getProviders(workspaceId: string, pagination: PaginationOptions) {
    return this.authProviderRepo.findByWorkspaceIdPaginated(
      workspaceId,
      pagination,
    );
  }

  async getProvider(
    providerId: string,
    workspaceId: string,
  ): Promise<AuthProvider> {
    const provider = await this.authProviderRepo.findById(
      providerId,
      workspaceId,
    );
    if (!provider) {
      throw new NotFoundException('SSO provider not found');
    }
    return provider;
  }

  /**
   * Creates a bare, disabled provider so the admin UI can immediately show the
   * callback URL (which embeds the generated id) for pasting into the identity
   * provider. The real configuration arrives via a subsequent update.
   */
  async create(
    dto: CreateSsoProviderDto,
    user: User,
    workspaceId: string,
  ): Promise<AuthProvider> {
    const provider = await this.authProviderRepo.insertProvider({
      name: dto.name,
      type: dto.type,
      workspaceId,
      creatorId: user.id,
      isEnabled: false,
      allowSignup: false,
    });

    this.auditService.log({
      event: AuditEvent.SSO_PROVIDER_CREATED,
      resourceType: AuditResource.SSO_PROVIDER,
      resourceId: provider.id,
      changes: { after: { name: provider.name, type: provider.type } },
    });

    return provider;
  }

  async update(
    dto: UpdateSsoProviderDto,
    workspaceId: string,
  ): Promise<AuthProvider> {
    const existing = await this.getProvider(dto.providerId, workspaceId);

    // Only copy keys the client actually sent. The form submits dirty fields
    // only, so an unconditional copy would null a working client secret every
    // time an admin edits just the display name.
    const updatable: UpdatableAuthProvider = {};
    for (const key of [
      'name',
      'oidcIssuer',
      'oidcClientId',
      'oidcClientSecret',
      'isEnabled',
      'allowSignup',
      'groupSync',
    ] as const) {
      if (typeof dto[key] !== 'undefined') {
        (updatable as Record<string, unknown>)[key] = dto[key];
      }
    }

    const merged = { ...existing, ...updatable };

    if (merged.type === SsoProviderType.OIDC) {
      await this.validateOidcConfig(merged, dto);
    }

    const provider = await this.authProviderRepo.updateProvider(
      updatable,
      dto.providerId,
      workspaceId,
    );

    const changes = diffAuditTrackedFields(
      AUDIT_TRACKED_FIELDS,
      dto,
      existing,
      provider,
    );

    this.auditService.log({
      event: AuditEvent.SSO_PROVIDER_UPDATED,
      resourceType: AuditResource.SSO_PROVIDER,
      resourceId: provider.id,
      ...(changes ? { changes } : {}),
      // Record THAT the secret rotated, never its value.
      ...(typeof dto.oidcClientSecret !== 'undefined'
        ? { metadata: { secretChanged: true } }
        : {}),
    });

    return provider;
  }

  async delete(providerId: string, workspaceId: string): Promise<void> {
    const provider = await this.getProvider(providerId, workspaceId);

    await this.authProviderRepo.deleteProvider(providerId, workspaceId);

    this.auditService.log({
      event: AuditEvent.SSO_PROVIDER_DELETED,
      resourceType: AuditResource.SSO_PROVIDER,
      resourceId: providerId,
      changes: { before: { name: provider.name, type: provider.type } },
    });
  }

  /**
   * Fail fast on a broken OIDC configuration rather than shipping a login
   * button that dead-ends at the identity provider.
   */
  private async validateOidcConfig(
    merged: OidcProviderConfig,
    dto: UpdateSsoProviderDto,
  ): Promise<void> {
    const issuerChanged = typeof dto.oidcIssuer !== 'undefined';
    const enabling = dto.isEnabled === true;

    if (
      merged.oidcIssuer &&
      MULTI_TENANT_ISSUER_PATTERN.test(merged.oidcIssuer)
    ) {
      throw new BadRequestException(
        'Use your tenant-specific Entra ID issuer (https://login.microsoftonline.com/<tenant-id>/v2.0). ' +
          'The "common", "organizations" and "consumers" endpoints publish a templated issuer that fails ' +
          'ID token validation, and would allow any Microsoft tenant to sign in.',
      );
    }

    if (enabling) {
      const missing = (
        ['oidcIssuer', 'oidcClientId', 'oidcClientSecret'] as const
      ).filter((field) => !merged[field]);

      if (missing.length > 0) {
        throw new BadRequestException(
          `Cannot enable this provider until the following are set: ${missing.join(', ')}.`,
        );
      }
    }

    // Probe discovery when the issuer changes or the provider is being switched
    // on, so a typo surfaces here instead of on someone's login attempt.
    if (merged.oidcIssuer && (issuerChanged || enabling)) {
      try {
        await this.oidcService.discover(merged, { skipCache: true });
      } catch (err) {
        this.logger.warn(
          `OIDC discovery failed for provider ${merged.id}: ${(err as Error)?.message}`,
        );
        throw new BadRequestException(
          `Could not reach the OIDC discovery document at ${merged.oidcIssuer}/.well-known/openid-configuration. ` +
            'Check the issuer URL and that this server can reach it.',
        );
      }
    }
  }
}
