import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { EnvironmentService } from '../../integrations/environment/environment.service';
import { AuthModule } from '../auth/auth.module';
import { SsoController } from './sso.controller';
import { OidcController } from './oidc.controller';
import { SsoService } from './services/sso.service';
import { OidcService } from './services/oidc.service';
import { OidcStateService } from './services/oidc-state.service';
import { SsoIdentityService } from './services/sso-identity.service';
import { OIDC_STATE_JWT_ISSUER, OIDC_STATE_TTL } from './sso.constants';

/**
 * Self-hosted OIDC single sign-on.
 *
 * Kept as a standalone module rather than folded into AuthModule so that it can
 * be removed with one line from CoreModule. Docmost's `ee` submodule registers
 * its own @Controller('sso'), and two controllers on the same path crash Fastify
 * at boot — so if that submodule is ever initialized, this module is what gets
 * dropped.
 *
 * AuthModule is imported for SignupService (which owns default-group
 * assignment). CaslModule, EnvironmentModule, SessionModule and DatabaseModule
 * are all @Global() and must not be imported here.
 */
@Module({
  imports: [
    AuthModule,
    // Module-scoped JWT instance for signing OIDC flow state. Deliberately
    // separate from TokenModule/TokenService: state tokens are a different
    // lifetime and audience, and reusing the shared service would mean editing
    // two more upstream files for no benefit.
    JwtModule.registerAsync({
      useFactory: async (environmentService: EnvironmentService) => ({
        secret: environmentService.getAppSecret(),
        signOptions: {
          expiresIn: OIDC_STATE_TTL,
          issuer: OIDC_STATE_JWT_ISSUER,
        },
      }),
      inject: [EnvironmentService],
    }),
  ],
  controllers: [SsoController, OidcController],
  providers: [
    SsoService,
    OidcService,
    OidcStateService,
    SsoIdentityService,
  ],
  exports: [SsoService, OidcService],
})
export class SsoModule {}
