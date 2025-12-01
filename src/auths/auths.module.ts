import { Module } from '@nestjs/common';
import { AuthsController } from './auths.controller';
import { AuthsService } from './auths.service';
import { UsersModule } from 'src/users/users.module';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { LocalStrategy } from './strategy/local.strategy';
import { JwtStrategy } from './strategy/jwt.strategy';

@Module({
  imports: [
    UsersModule,
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secretOrPrivateKey: configService.get<string>('JWT_SECRET')!,
        signOptions: {
          expiresIn: configService.get('JWT_EXPIRATION_TIME')!,
        },
      }),
    }),
  ],
  controllers: [AuthsController],
  providers: [AuthsService, LocalStrategy, JwtStrategy],
})
export class AuthsModule {}
