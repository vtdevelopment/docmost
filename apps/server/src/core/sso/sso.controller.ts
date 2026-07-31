import {
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';
import { SkipThrottle } from '@nestjs/throttler';
import {
  AI_CHAT_THROTTLER,
  AUTH_THROTTLER,
} from '../../integrations/throttle/throttler-names';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { AuthUser } from '../../common/decorators/auth-user.decorator';
import { AuthWorkspace } from '../../common/decorators/auth-workspace.decorator';
import { User, Workspace } from '@docmost/db/types/entity.types';
import { PaginationOptions } from '@docmost/db/pagination/pagination-options';
import { WorkspaceRepo } from '@docmost/db/repos/workspace/workspace.repo';
import WorkspaceAbilityFactory from '../casl/abilities/workspace-ability.factory';
import {
  WorkspaceCaslAction,
  WorkspaceCaslSubject,
} from '../casl/interfaces/workspace-ability.type';
import { LicenseCheckService } from '../../integrations/environment/license-check.service';
import { Feature } from '../../common/features';
import { SsoService } from './services/sso.service';
import { CreateSsoProviderDto } from './dto/create-sso-provider.dto';
import { UpdateSsoProviderDto } from './dto/update-sso-provider.dto';
import { SsoProviderIdDto } from './dto/sso-provider-id.dto';

/**
 * Admin CRUD for SSO providers.
 *
 * Route shape is dictated by the existing client:
 * apps/client/src/ee/security/services/security-service.ts
 *
 * These are JWT-guarded admin calls, so they are exempted from the strict auth
 * throttle bucket (10/60s) which would otherwise cause false positives.
 */
@SkipThrottle({ [AUTH_THROTTLER]: true, [AI_CHAT_THROTTLER]: true })
@UseGuards(JwtAuthGuard)
@Controller('sso')
export class SsoController {
  constructor(
    private readonly ssoService: SsoService,
    private readonly workspaceAbility: WorkspaceAbilityFactory,
    private readonly workspaceRepo: WorkspaceRepo,
    private readonly licenseCheckService: LicenseCheckService,
  ) {}

  @HttpCode(HttpStatus.OK)
  @Post('providers')
  async getProviders(
    // The client sends no body for this call, so every field must stay
    // optional; PaginationOptions defaults limit to 20.
    @Body() pagination: PaginationOptions,
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    await this.authorize(user, workspace);
    return this.ssoService.getProviders(workspace.id, pagination);
  }

  @HttpCode(HttpStatus.OK)
  @Post('info')
  async getProvider(
    @Body() dto: SsoProviderIdDto,
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    await this.authorize(user, workspace);
    return this.ssoService.getProvider(dto.providerId, workspace.id);
  }

  @HttpCode(HttpStatus.OK)
  @Post('create')
  async createProvider(
    @Body() dto: CreateSsoProviderDto,
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    await this.authorize(user, workspace);
    return this.ssoService.create(dto, user, workspace.id);
  }

  @HttpCode(HttpStatus.OK)
  @Post('update')
  async updateProvider(
    @Body() dto: UpdateSsoProviderDto,
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    await this.authorize(user, workspace);
    return this.ssoService.update(dto, workspace.id);
  }

  @HttpCode(HttpStatus.OK)
  @Post('delete')
  async deleteProvider(
    @Body() dto: SsoProviderIdDto,
    @AuthUser() user: User,
    @AuthWorkspace() workspace: Workspace,
  ) {
    await this.authorize(user, workspace);
    return this.ssoService.delete(dto.providerId, workspace.id);
  }

  /**
   * `Manage` rather than `Read`, even for the list: the payload carries the
   * issuer, client id and client secret, which ordinary members (who do hold
   * Read on Settings) have no business seeing.
   */
  private async authorize(user: User, workspace: Workspace): Promise<void> {
    const ability = this.workspaceAbility.createForUser(user, workspace);
    if (
      ability.cannot(WorkspaceCaslAction.Manage, WorkspaceCaslSubject.Settings)
    ) {
      throw new ForbiddenException();
    }

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
      throw new ForbiddenException(
        'Single sign-on is not enabled on this instance.',
      );
    }
  }
}
