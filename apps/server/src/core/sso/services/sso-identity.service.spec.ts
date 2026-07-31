import { BadRequestException } from '@nestjs/common';
import {
  SignupDisabledError,
  SsoIdentityService,
} from './sso-identity.service';
import { OidcIdentity } from './oidc.service';

const WORKSPACE_ID = 'ws-1';
const PROVIDER_ID = 'prov-1';

const provider = {
  id: PROVIDER_ID,
  allowSignup: true,
} as any;

const workspace = { id: WORKSPACE_ID } as any;

const identity: OidcIdentity = {
  providerUserId: 'entra-sub-123',
  email: 'alice@corp.com',
  name: 'Alice',
};

function build(overrides?: {
  authAccount?: any;
  userById?: any;
  userByEmail?: any;
  signupImpl?: jest.Mock;
}) {
  const authAccountRepo = {
    findByProviderUserId: jest
      .fn()
      .mockResolvedValue(overrides?.authAccount ?? undefined),
    insertAuthAccount: jest.fn().mockResolvedValue({ id: 'aa-1' }),
  };

  const userRepo = {
    findById: jest.fn().mockResolvedValue(overrides?.userById ?? undefined),
    findByEmail: jest.fn().mockResolvedValue(overrides?.userByEmail ?? undefined),
    updateUser: jest.fn().mockResolvedValue(undefined),
  };

  const signupService = {
    signup:
      overrides?.signupImpl ??
      jest.fn().mockResolvedValue({
        id: 'user-new',
        email: identity.email,
        name: identity.name,
      }),
  };

  // executeTx with no existing trx calls db.transaction().execute(cb)
  const db = {
    transaction: () => ({
      execute: (cb: (trx: any) => Promise<any>) => cb({} as any),
    }),
  };

  const auditService = { log: jest.fn(), setActorId: jest.fn() };

  const service = new SsoIdentityService(
    authAccountRepo as any,
    userRepo as any,
    signupService as any,
    db as any,
    auditService as any,
  );

  return { service, authAccountRepo, userRepo, signupService, auditService };
}

describe('SsoIdentityService.findOrProvision', () => {
  describe('branch A: identity already linked', () => {
    it('returns the linked user without creating anything', async () => {
      const existing = { id: 'user-1', email: identity.email };
      const { service, userRepo, signupService, authAccountRepo } = build({
        authAccount: { userId: 'user-1' },
        userById: existing,
      });

      const result = await service.findOrProvision({
        provider,
        workspace,
        identity,
      });

      expect(result).toBe(existing);
      expect(userRepo.findById).toHaveBeenCalledWith('user-1', WORKSPACE_ID);
      expect(signupService.signup).not.toHaveBeenCalled();
      expect(authAccountRepo.insertAuthAccount).not.toHaveBeenCalled();
    });

    it('signs in even when signup is disabled', async () => {
      // allowSignup gates creation, not login.
      const existing = { id: 'user-1', email: identity.email };
      const { service } = build({
        authAccount: { userId: 'user-1' },
        userById: existing,
      });

      await expect(
        service.findOrProvision({
          provider: { ...provider, allowSignup: false },
          workspace,
          identity,
        }),
      ).resolves.toBe(existing);
    });

    it('does not overwrite a locally-changed email', async () => {
      const existing = { id: 'user-1', email: 'alice.renamed@corp.com' };
      const { service, userRepo } = build({
        authAccount: { userId: 'user-1' },
        userById: existing,
      });

      const result = await service.findOrProvision({
        provider,
        workspace,
        identity,
      });

      expect(result.email).toBe('alice.renamed@corp.com');
      expect(userRepo.updateUser).not.toHaveBeenCalled();
    });

    it('falls through when the linked user row is gone', async () => {
      // Hard-deleted user: re-resolve rather than returning undefined.
      const { service, signupService } = build({
        authAccount: { userId: 'user-gone' },
        userById: undefined,
        userByEmail: undefined,
      });

      await service.findOrProvision({ provider, workspace, identity });

      expect(signupService.signup).toHaveBeenCalled();
    });
  });

  describe('branch B: existing account with the same email', () => {
    it('links the identity and signs in without creating a user', async () => {
      const existing = { id: 'user-2', email: identity.email };
      const { service, authAccountRepo, signupService } = build({
        userByEmail: existing,
      });

      const result = await service.findOrProvision({
        provider,
        workspace,
        identity,
      });

      expect(result).toBe(existing);
      expect(signupService.signup).not.toHaveBeenCalled();
      expect(authAccountRepo.insertAuthAccount).toHaveBeenCalledWith({
        userId: 'user-2',
        providerUserId: identity.providerUserId,
        authProviderId: PROVIDER_ID,
        workspaceId: WORKSPACE_ID,
      });
    });

    it('links even when signup is disabled', async () => {
      const existing = { id: 'user-2', email: identity.email };
      const { service, authAccountRepo } = build({ userByEmail: existing });

      await expect(
        service.findOrProvision({
          provider: { ...provider, allowSignup: false },
          workspace,
          identity,
        }),
      ).resolves.toBe(existing);
      expect(authAccountRepo.insertAuthAccount).toHaveBeenCalled();
    });

    it('records the link in the audit log', async () => {
      const { service, auditService } = build({
        userByEmail: { id: 'user-2', email: identity.email },
      });

      await service.findOrProvision({ provider, workspace, identity });

      expect(auditService.log).toHaveBeenCalledWith(
        expect.objectContaining({
          metadata: expect.objectContaining({ linked: true }),
        }),
      );
    });
  });

  describe('branch C: just-in-time provisioning', () => {
    it('creates the user through SignupService, which assigns the default group', async () => {
      const { service, signupService, userRepo, authAccountRepo } = build();

      const result = await service.findOrProvision({
        provider,
        workspace,
        identity,
      });

      expect(result.id).toBe('user-new');

      // SignupService.signup is what runs addUserToDefaultGroup, so going
      // through it is what puts SSO users in "Everyone".
      expect(signupService.signup).toHaveBeenCalledTimes(1);
      const [dto, workspaceId, trx] = signupService.signup.mock.calls[0];
      expect(workspaceId).toBe(WORKSPACE_ID);
      expect(trx).toBeDefined();
      expect(dto.email).toBe(identity.email);
      expect(dto.name).toBe(identity.name);

      // insertUser bcrypt-hashes this unconditionally and rejects undefined.
      expect(typeof dto.password).toBe('string');
      expect(dto.password.length).toBeGreaterThanOrEqual(8);

      expect(userRepo.updateUser).toHaveBeenCalledWith(
        expect.objectContaining({
          hasGeneratedPassword: true,
          emailVerifiedAt: expect.any(Date),
        }),
        'user-new',
        WORKSPACE_ID,
        expect.anything(),
      );

      expect(authAccountRepo.insertAuthAccount).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: 'user-new',
          providerUserId: identity.providerUserId,
          authProviderId: PROVIDER_ID,
        }),
        expect.anything(),
      );
    });

    it('marks the returned user as SSO-provisioned and verified', async () => {
      const { service } = build();

      const result = await service.findOrProvision({
        provider,
        workspace,
        identity,
      });

      expect(result.hasGeneratedPassword).toBe(true);
      expect(result.emailVerifiedAt).toBeInstanceOf(Date);
    });

    it('generates a distinct password per user', async () => {
      const { service, signupService } = build();
      await service.findOrProvision({ provider, workspace, identity });
      await service.findOrProvision({ provider, workspace, identity });

      const first = signupService.signup.mock.calls[0][0].password;
      const second = signupService.signup.mock.calls[1][0].password;
      expect(first).not.toBe(second);
    });

    it('rejects an unknown user when signup is disabled', async () => {
      const { service, signupService } = build();

      await expect(
        service.findOrProvision({
          provider: { ...provider, allowSignup: false },
          workspace,
          identity,
        }),
      ).rejects.toBeInstanceOf(SignupDisabledError);

      expect(signupService.signup).not.toHaveBeenCalled();
    });

    it('retries as a link when a concurrent signup wins the race', async () => {
      // Two simultaneous first-ever logins: the loser must resolve via branch B
      // rather than surfacing "account already exists".
      const raced = { id: 'user-raced', email: identity.email };
      let call = 0;

      const signupImpl = jest.fn().mockImplementation(() => {
        call += 1;
        throw new BadRequestException(
          'An account with this email already exists in this workspace',
        );
      });

      const { service, authAccountRepo, userRepo } = build({ signupImpl });
      // First lookup misses, the retry finds the row the winner just inserted.
      userRepo.findByEmail
        .mockResolvedValueOnce(undefined)
        .mockResolvedValueOnce(raced);

      const result = await service.findOrProvision({
        provider,
        workspace,
        identity,
      });

      expect(result).toBe(raced);
      expect(call).toBe(1);
      expect(authAccountRepo.insertAuthAccount).toHaveBeenCalledWith(
        expect.objectContaining({ userId: 'user-raced' }),
      );
    });

    it('propagates unrelated signup failures', async () => {
      const signupImpl = jest
        .fn()
        .mockRejectedValue(new Error('database is on fire'));
      const { service } = build({ signupImpl });

      await expect(
        service.findOrProvision({ provider, workspace, identity }),
      ).rejects.toThrow('database is on fire');
    });
  });
});
