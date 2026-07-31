import { IsUUID } from 'class-validator';

export class SsoProviderIdDto {
  @IsUUID()
  providerId: string;
}
