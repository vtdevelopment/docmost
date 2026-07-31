import { Injectable } from '@nestjs/common';
import { InjectKysely } from 'nestjs-kysely';
import { KyselyDB, KyselyTransaction } from '@docmost/db/types/kysely.types';
import { dbOrTx } from '@docmost/db/utils';
import {
  AuthProvider,
  InsertableAuthProvider,
  UpdatableAuthProvider,
} from '@docmost/db/types/entity.types';
import { AuthProviders } from '@docmost/db/types/db';
import { PaginationOptions } from '../../pagination/pagination-options';
import { executeWithCursorPagination } from '@docmost/db/pagination/cursor-pagination';
import { SsoProviderType } from '../../../core/sso/sso.constants';

@Injectable()
export class AuthProviderRepo {
  constructor(@InjectKysely() private readonly db: KyselyDB) {}

  /**
   * `oidcClientSecret` IS included, deliberately.
   *
   * The admin edit modal is populated straight from the list response — see
   * sso-provider-list.tsx, which passes the list row into the modal with no
   * re-fetch — and the OIDC form's zod schema declares
   * `oidcClientSecret: z.string().min(1)`. Omitting the secret would leave that
   * field blank, fail validation, and make it impossible to save ANY edit,
   * including just renaming the provider.
   *
   * Every route that returns this projection is admin-gated (CASL Manage on
   * Settings). The secret is never audited and never logged.
   *
   * `ldapBindPassword`, `ldapConfig` and `settings` are excluded — nothing reads
   * them, so there is no reason to put them on the wire.
   */
  private baseFields: Array<keyof AuthProviders> = [
    'id',
    'name',
    'type',
    'samlUrl',
    'samlCertificate',
    'oidcIssuer',
    'oidcClientId',
    'oidcClientSecret',
    'ldapUrl',
    'ldapBindDn',
    'ldapBaseDn',
    'ldapUserSearchFilter',
    'ldapUserAttributes',
    'ldapTlsEnabled',
    'ldapTlsCaCert',
    'allowSignup',
    'isEnabled',
    'groupSync',
    'creatorId',
    'workspaceId',
    'createdAt',
    'updatedAt',
    'deletedAt',
  ];

  async findById(
    providerId: string,
    workspaceId: string,
    opts?: { trx?: KyselyTransaction },
  ): Promise<AuthProvider> {
    const db = dbOrTx(this.db, opts?.trx);
    return db
      .selectFrom('authProviders')
      .select(this.baseFields)
      .where('id', '=', providerId)
      .where('workspaceId', '=', workspaceId)
      .where('deletedAt', 'is', null)
      .executeTakeFirst();
  }

  /**
   * The login/callback hot path. Resolves a provider only if it is usable:
   * right type, enabled, not deleted.
   */
  async findEnabledOidcById(
    providerId: string,
    workspaceId: string,
    opts?: { trx?: KyselyTransaction },
  ): Promise<AuthProvider> {
    const db = dbOrTx(this.db, opts?.trx);
    return db
      .selectFrom('authProviders')
      .select(this.baseFields)
      .where('id', '=', providerId)
      .where('workspaceId', '=', workspaceId)
      .where('type', '=', SsoProviderType.OIDC)
      .where('isEnabled', '=', true)
      .where('deletedAt', 'is', null)
      .executeTakeFirst();
  }

  async findByWorkspaceIdPaginated(
    workspaceId: string,
    pagination: PaginationOptions,
  ) {
    const query = this.db
      .selectFrom('authProviders')
      .select(this.baseFields)
      .where('workspaceId', '=', workspaceId)
      .where('deletedAt', 'is', null);

    return executeWithCursorPagination(query, {
      perPage: pagination?.limit ?? 20,
      cursor: pagination?.cursor,
      beforeCursor: pagination?.beforeCursor,
      fields: [
        { expression: 'createdAt', direction: 'asc', key: 'createdAt' },
        { expression: 'id', direction: 'asc', key: 'id' },
      ],
      parseCursor: (cursor) => ({
        createdAt: new Date(cursor.createdAt),
        id: cursor.id,
      }),
    });
  }

  async insertProvider(
    insertable: InsertableAuthProvider,
    trx?: KyselyTransaction,
  ): Promise<AuthProvider> {
    const db = dbOrTx(this.db, trx);
    return db
      .insertInto('authProviders')
      .values(insertable)
      .returning(this.baseFields)
      .executeTakeFirst();
  }

  async updateProvider(
    updatable: UpdatableAuthProvider,
    providerId: string,
    workspaceId: string,
    trx?: KyselyTransaction,
  ): Promise<AuthProvider> {
    const db = dbOrTx(this.db, trx);
    return db
      .updateTable('authProviders')
      .set({ ...updatable, updatedAt: new Date() })
      .where('id', '=', providerId)
      .where('workspaceId', '=', workspaceId)
      .where('deletedAt', 'is', null)
      .returning(this.baseFields)
      .executeTakeFirst();
  }

  /**
   * Hard delete, not a soft delete.
   *
   * `WorkspaceService.getWorkspacePublicData` and the `enforceSso` precheck both
   * query `authProviders` WITHOUT a `deletedAt` filter, so a soft-deleted row
   * would keep rendering a button on the login page and keep satisfying the
   * "at least one enabled provider" check.
   *
   * Consequence: `auth_accounts.auth_provider_id` is ON DELETE CASCADE, so this
   * destroys every identity link. JIT-provisioned users hold random generated
   * passwords and cannot sign in until the provider is re-created (which
   * re-links them by email on next login) or they use forgot-password. Admins
   * should disable rather than delete; the UI copy should say so.
   */
  async deleteProvider(providerId: string, workspaceId: string): Promise<void> {
    await this.db
      .deleteFrom('authProviders')
      .where('id', '=', providerId)
      .where('workspaceId', '=', workspaceId)
      .execute();
  }

  async countEnabled(workspaceId: string): Promise<number> {
    const { count } = await this.db
      .selectFrom('authProviders')
      .select((eb) => eb.fn.countAll().as('count'))
      .where('workspaceId', '=', workspaceId)
      .where('isEnabled', '=', true)
      .where('deletedAt', 'is', null)
      .executeTakeFirst();

    return Number(count);
  }
}
