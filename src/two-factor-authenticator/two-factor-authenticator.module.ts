import { Module } from '@nestjs/common';
import { TwoFactorAuthenticatorService } from './two-factor-authenticator.service';
import { TwoFactorAuthenticatorController } from './two-factor-authenticator.controller';
import { UsersModule } from 'src/users/users.module';
import { AuthsModule } from 'src/auths/auths.module';

@Module({
  imports: [UsersModule, AuthsModule],
  providers: [TwoFactorAuthenticatorService],
  controllers: [TwoFactorAuthenticatorController]
})
export class TwoFactorAuthenticatorModule {}
