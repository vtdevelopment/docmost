import { IsIn, IsNotEmpty, IsString, MaxLength } from 'class-validator';
import { Transform, TransformFnParams } from 'class-transformer';
import { SsoProviderType } from '../sso.constants';

/**
 * The create menu in the admin UI posts only `{type, name}` and expects the
 * created provider (with its generated id) back, so the modal can show the
 * callback URL. See apps/client/src/ee/security/components/create-sso-provider.tsx
 */
export class CreateSsoProviderDto {
  @IsNotEmpty()
  @IsString()
  @MaxLength(60)
  @Transform(({ value }: TransformFnParams) => value?.trim())
  name: string;

  /**
   * Only OIDC is implemented on this build. The client's create menu also
   * offers SAML and LDAP; accepting those would persist a provider row that
   * renders a permanently broken button on the login page, so they are rejected
   * here with a clear message instead.
   */
  @IsNotEmpty()
  @IsIn([SsoProviderType.OIDC], {
    message:
      'Only OIDC single sign-on is available on this instance. SAML, LDAP and Google are not implemented.',
  })
  type: string;
}
