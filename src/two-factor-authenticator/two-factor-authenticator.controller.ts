import {
  Body,
  Controller,
  HttpCode,
  Post,
  Req,
  Res,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { TwoFactorAuthenticatorService } from './two-factor-authenticator.service';
import { JwtAuthGuard } from 'src/auths/guard/jwt.guard';
import { LoggedInUser } from 'src/auths/decorator/current-user.decorator';
import { User } from 'src/users/model/user.entity';
import { Request, Response } from 'express';
import { TwoFactorAuthenticationCodeDto } from './dto/two-factor-authentication.dto';
import { UsersService } from 'src/users/users.service';
import { AuthsService } from 'src/auths/auths.service';

@Controller('2fa')
export class TwoFactorAuthenticatorController {
  constructor(
    private readonly twoFactorAuthenticatorService: TwoFactorAuthenticatorService,
    private readonly usersService: UsersService,
    private readonly authsService: AuthsService,
  ) {}

  @Post('authenticate')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  async authenticate(
    @LoggedInUser() user: User,
    @Req() request: Request,
    @Body() { twoFactorAuthenticationCode }: TwoFactorAuthenticationCodeDto,
  ) {
    const isValidCode =
      await this.twoFactorAuthenticatorService.isTwoFactorAuthencationCodeValid(
        twoFactorAuthenticationCode,
        user,
      );

    if (isValidCode) {
      throw new UnauthorizedException('Wrong authentication code');
    }

    const accessTokenCookie =
      await this.authsService.getCookieWithJwtAccessToken(user.id, true);

      request.res?.setHeader('Set-Cookie', accessTokenCookie)

      return user
  }

  @Post('turn-on')
  @HttpCode(200)
  @UseGuards(JwtAuthGuard)
  async turnOnTwoFactorAuthentication(
    @LoggedInUser() user: User,
    @Body() { twoFactorAuthenticationCode }: TwoFactorAuthenticationCodeDto,
  ) {
    const isCodeValid =
      await this.twoFactorAuthenticatorService.isTwoFactorAuthencationCodeValid(
        twoFactorAuthenticationCode,
        user,
      );

    if (!isCodeValid) {
      throw new UnauthorizedException('Wrong authentication code');
    }

    await this.usersService.turnOnTwoFactorAuthentication(user.id);

    return {
      message: '2FA turned on',
    };
  }

  @Post('generate')
  @UseGuards(JwtAuthGuard)
  async register(@LoggedInUser() user: User, @Res() response: Response) {
    const { otpauthUrl } =
      await this.twoFactorAuthenticatorService.generateTwoFactorAuthenticationSecret(
        user,
      );

    return this.twoFactorAuthenticatorService.pipeQrCodeStream(
      response,
      otpauthUrl,
    );
  }
}
