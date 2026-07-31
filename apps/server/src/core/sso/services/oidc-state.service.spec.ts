import { JwtService } from '@nestjs/jwt';
import type { StringValue } from 'ms';
import { OidcStateService, OidcStatePayload } from './oidc-state.service';
import { OIDC_STATE_JWT_ISSUER, OIDC_STATE_TTL } from '../sso.constants';

const SECRET = 'a'.repeat(48);

function buildService(opts?: {
  secret?: string;
  expiresIn?: StringValue;
  issuer?: string;
}) {
  const jwtService = new JwtService({
    secret: opts?.secret ?? SECRET,
    signOptions: {
      expiresIn: opts?.expiresIn ?? OIDC_STATE_TTL,
      issuer: opts?.issuer ?? OIDC_STATE_JWT_ISSUER,
    },
  });

  const environmentService = {
    getAppSecret: () => SECRET,
    isHttps: () => false,
  } as any;

  return new OidcStateService(jwtService, environmentService);
}

const payload: OidcStatePayload = {
  p: '018f1b2c-0000-7000-8000-000000000001',
  s: 'state-value',
  n: 'nonce-value',
  v: 'pkce-code-verifier-value',
  r: '/settings/account/profile',
};

describe('OidcStateService', () => {
  it('round-trips a payload', async () => {
    const service = buildService();
    const token = await service.sign(payload);
    const verified = await service.verify(token);

    expect(verified.p).toBe(payload.p);
    expect(verified.s).toBe(payload.s);
    expect(verified.n).toBe(payload.n);
    expect(verified.v).toBe(payload.v);
    expect(verified.r).toBe(payload.r);
  });

  it('preserves a null redirect', async () => {
    const service = buildService();
    const token = await service.sign({ ...payload, r: null });
    await expect(service.verify(token)).resolves.toMatchObject({ r: null });
  });

  it('rejects a tampered payload', async () => {
    const service = buildService();
    const token = await service.sign(payload);

    // Re-encode the body with a different provider id, keeping the signature.
    const [header, body, signature] = token.split('.');
    const decoded = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    decoded.p = '018f1b2c-0000-7000-8000-0000000000ff';
    const forged = Buffer.from(JSON.stringify(decoded)).toString('base64url');

    await expect(
      service.verify(`${header}.${forged}.${signature}`),
    ).rejects.toThrow();
  });

  it('rejects a token signed with a different secret', async () => {
    // Verification always uses APP_SECRET, so a token minted elsewhere fails.
    const foreign = buildService({ secret: 'b'.repeat(48) });
    const token = await foreign.sign(payload);

    await expect(buildService().verify(token)).rejects.toThrow();
  });

  it('rejects an expired token', async () => {
    const expired = buildService({ expiresIn: '-1s' });
    const token = await expired.sign(payload);

    await expect(buildService().verify(token)).rejects.toThrow();
  });

  it('rejects a token with a different issuer', async () => {
    // Guards against an auth token being replayed as flow state.
    const other = buildService({ issuer: 'Docmost' });
    const token = await other.sign(payload);

    await expect(buildService().verify(token)).rejects.toThrow();
  });

  it('rejects a structurally invalid token', async () => {
    const service = buildService();
    await expect(service.verify('not-a-jwt')).rejects.toThrow();
    await expect(service.verify('')).rejects.toThrow();
  });
});
