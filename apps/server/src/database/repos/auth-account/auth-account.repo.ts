import { Injectable } from '@nestjs/common';
import { InjectKysely } from 'nestjs-kysely';
import { KyselyDB, KyselyTransaction } from '@docmost/db/types/kysely.types';
import { dbOrTx } from '@docmost/db/utils';
import {
  AuthAccount,
  InsertableAuthAccount,
} from '@docmost/db/types/entity.types';
import { AuthAccounts } from '@docmost/db/types/db';

@Injectable()
export class AuthAccountRepo {
  constructor(@InjectKysely() private readonly db: KyselyDB) {}

  private baseFields: Array<keyof AuthAccounts> = [
    'id',
    'userId',
    'providerUserId',
    'authProviderId',
    'workspaceId',
    'createdAt',
    'updatedAt',
    'deletedAt',
  ];

  async findByProviderUserId(
    providerUserId: string,
    authProviderId: string,
    workspaceId: string,
    opts?: { trx?: KyselyTransaction },
  ): Promise<AuthAccount> {
    const db = dbOrTx(this.db, opts?.trx);
    return db
      .selectFrom('authAccounts')
      .select(this.baseFields)
      .where('providerUserId', '=', providerUserId)
      .where('authProviderId', '=', authProviderId)
      .where('workspaceId', '=', workspaceId)
      .where('deletedAt', 'is', null)
      .executeTakeFirst();
  }

  async findByUserAndProvider(
    userId: string,
    authProviderId: string,
    opts?: { trx?: KyselyTransaction },
  ): Promise<AuthAccount> {
    const db = dbOrTx(this.db, opts?.trx);
    return db
      .selectFrom('authAccounts')
      .select(this.baseFields)
      .where('userId', '=', userId)
      .where('authProviderId', '=', authProviderId)
      .where('deletedAt', 'is', null)
      .executeTakeFirst();
  }

  /**
   * Idempotent on the existing `auth_accounts_user_id_auth_provider_id_unique`
   * constraint, so a repeated login or a concurrent first login cannot 500.
   *
   * The `providerUserId` is refreshed on conflict: Entra's `sub` is pairwise per
   * app registration, so if the Entra app is ever re-created the same user comes
   * back with a new subject and links cleanly to their existing row.
   */
  async insertAuthAccount(
    insertable: InsertableAuthAccount,
    trx?: KyselyTransaction,
  ): Promise<AuthAccount> {
    const db = dbOrTx(this.db, trx);
    return db
      .insertInto('authAccounts')
      .values(insertable)
      .onConflict((oc) =>
        oc.columns(['userId', 'authProviderId']).doUpdateSet({
          providerUserId: insertable.providerUserId,
          updatedAt: new Date(),
        }),
      )
      .returning(this.baseFields)
      .executeTakeFirst();
  }

  async deleteByProviderId(
    authProviderId: string,
    trx?: KyselyTransaction,
  ): Promise<void> {
    const db = dbOrTx(this.db, trx);
    await db
      .deleteFrom('authAccounts')
      .where('authProviderId', '=', authProviderId)
      .execute();
  }
}
