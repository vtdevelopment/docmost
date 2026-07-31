import {
  IsBoolean,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUrl,
  IsUUID,
  MaxLength,
  MinLength,
} from 'class-validator';
import { Transform, TransformFnParams } from 'class-transformer';

/**
 * The OIDC admin form sends ONLY the fields the admin actually touched
 * (`form.isDirty(field)` — see
 * apps/client/src/ee/security/components/sso-oidc-form.tsx), so every field here
 * is optional and the service must distinguish "absent" from "cleared".
 *
 * The global ValidationPipe runs with `whitelist: true`, so any field NOT
 * declared here is silently stripped from the body. Adding a form field without
 * adding it here makes it look saved while being discarded.
 */
export class UpdateSsoProviderDto {
  @IsUUID()
  providerId: string;

  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(60)
  @Transform(({ value }: TransformFnParams) => value?.trim())
  name?: string;

  @IsOptional()
  @IsUrl(
    { protocols: ['http', 'https'], require_tld: false },
    { message: 'oidcIssuer must be a valid http(s) URL' },
  )
  @MaxLength(500)
  @Transform(({ value }: TransformFnParams) => value?.trim())
  oidcIssuer?: string;

  @IsOptional()
  @IsNotEmpty()
  @IsString()
  @MaxLength(255)
  @Transform(({ value }: TransformFnParams) => value?.trim())
  oidcClientId?: string;

  @IsOptional()
  @IsNotEmpty()
  @IsString()
  @MaxLength(500)
  oidcClientSecret?: string;

  @IsOptional()
  @IsBoolean()
  isEnabled?: boolean;

  @IsOptional()
  @IsBoolean()
  allowSignup?: boolean;

  @IsOptional()
  @IsBoolean()
  groupSync?: boolean;
}
