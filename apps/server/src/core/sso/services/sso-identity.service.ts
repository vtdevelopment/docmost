import { BadRequestException, Inject, Injectable, Logger } from '@nestjs/common';
import { randomBytes } from 'node:crypto';
import { InjectKysely } from 'nestjs-kysely';
import { KyselyDB } from '@docmost/db/types/kysely.types';
import { executeTx } from '@docmost/db/utils';
import { AuthAccountRepo } from '@docmost/db/repos/auth-account/auth-account.repo';
import { UserRepo } from '@docmost/db/repos/user/user.repo';
import { AuthProvider, User, Workspace } from '@docmost/db/types/entity.types';
import { SignupService } from '../../auth/services/signup.service';
import { CreateUserDto } from '../../auth/dto/create-user.dto';
import { OidcIdentity } from './oidc.service';
import {
  AuditEvent,
  AuditResource,
} from '../../../common/events/audit-events';
import {
  AUDIT_SERVICE,
  IAuditService,
} from '../../../integrations/audit/audit.service';

/** Raised when an unknown user signs in and the provider has signup disabled. */
export class SignupDisabledError extends Error {
  constructor() {
    super('Signup via this SSO provider is disabled');
    this.name = 'SignupDisabledError';
  }
}

@Injectable()
export class SsoIdentityService {
  private readonly logger = new Logger(SsoIdentityService.name);

  constructor(
    private readonly authAccountRepo: AuthAccountRepo,
    private readonly userRepo: UserRepo,
    private readonly signupService: SignupService,
    @InjectKysely() private readonly db: KyselyDB,
    @Inject(AUDIT_SERVICE) private readonly auditService: IAuditService,
  ) {}

  /**
   * Resolves the Docmost user behind a verified SSO identity.
   *
   *   A. an auth_accounts row already links this provider subject -> sign in
   *   B. no link, but a user with this email exists            -> link, sign in
   *   C. neither                                              -> JIT create
   *
   * Note that `allowSignup` gates creation only. Users who already have an
   * account (A and B) must keep working when it is turned off.
   */
  async findOrProvision(opts: {
    provider: AuthProvider;
    workspace: Workspace;
    identity: OidcIdentity;
  }): Promise<User> {
    const { provider, workspace, identity } = opts;

    // --- A: known identity -------------------------------------------------
    const authAccount = await this.authAccountRepo.findByProviderUserId(
      identity.providerUserId,
      provider.id,
      workspace.id,
    );

    if (authAccount) {
      const user = await this.userRepo.findById(
        authAccount.userId,
        workspace.id,
      );
      if (user) {
        // Deliberately do NOT overwrite users.email from the IdP: that is a
        // silent identity change and could collide with another row's unique
        // (email, workspace_id).
        if (user.email !== identity.email) {
          this.logger.warn(
            `SSO email drift for user ${user.id}: local "${user.email}" vs provider claim. Keeping the local value.`,
          );
        }
        return user;
      }
      // The linked user row is gone (hard-deleted). Fall through and re-resolve.
    }

    // --- B: existing account with the same email ---------------------------
    const existingUser = await this.userRepo.findByEmail(
      identity.email,
      workspace.id,
    );

    if (existingUser) {
      await this.authAccountRepo.insertAuthAccount({
        userId: existingUser.id,
        providerUserId: identity.providerUserId,
        authProviderId: provider.id,
        workspaceId: workspace.id,
      });

      this.auditService.log({
        event: AuditEvent.USER_LOGIN,
        resourceType: AuditResource.USER,
        resourceId: existingUser.id,
        metadata: {
          source: 'sso:oidc',
          providerId: provider.id,
          linked: true,
        },
      });

      return existingUser;
    }

    // --- C: just-in-time provisioning --------------------------------------
    if (!provider.allowSignup) {
      throw new SignupDisabledError();
    }

    try {
      return await this.provisionUser(provider, workspace, identity);
    } catch (err) {
      // SignupService re-checks the email inside its own transaction, so two
      // simultaneous first-ever logins race here. The loser retries once, which
      // now resolves through branch B.
      if (
        err instanceof BadRequestException &&
        String(err.message).includes('already exists')
      ) {
        this.logger.warn(
          `Concurrent SSO signup for ${identity.email}; retrying as a link.`,
        );
        return this.findOrProvision(opts);
      }
      throw err;
    }
  }

  /**
   * Creates the user and links the identity in one transaction.
   *
   * SignupService.signup already does insertUser -> addUserToWorkspace (which
   * applies workspaces.default_role) -> addUserToDefaultGroup -> USER_CREATED
   * audit. That third step is what puts SSO users in the default "Everyone"
   * group, so it is reused rather than reimplemented.
   */
  private async provisionUser(
    provider: AuthProvider,
    workspace: Workspace,
    identity: OidcIdentity,
  ): Promise<User> {
    const now = new Date();

    return executeTx(this.db, async (trx) => {
      const user = await this.signupService.signup(
        {
          name: identity.name,
          email: identity.email,
          // UserRepo.insertUser unconditionally bcrypt-hashes this field, and
          // bcrypt rejects undefined — so a passwordless SSO user still needs a
          // value. It is never used: hasGeneratedPassword marks the account as
          // SSO-provisioned, and the user reaches a real password only via
          // forgot-password.
          password: randomBytes(32).toString('base64url'),
        } as CreateUserDto,
        workspace.id,
        trx,
      );

      await this.userRepo.updateUser(
        {
          hasGeneratedPassword: true,
          // The identity provider authenticated them, so the address is
          // verified as far as we are concerned.
          emailVerifiedAt: now,
        },
        user.id,
        workspace.id,
        trx,
      );

      await this.authAccountRepo.insertAuthAccount(
        {
          userId: user.id,
          providerUserId: identity.providerUserId,
          authProviderId: provider.id,
          workspaceId: workspace.id,
        },
        trx,
      );

      return {
        ...user,
        hasGeneratedPassword: true,
        emailVerifiedAt: now,
      };
    });
  }
}
