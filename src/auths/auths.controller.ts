import {
  Body,
  ClassSerializerInterceptor,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  SerializeOptions,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { AuthsService } from './auths.service';
import type { RequestWithUser } from './request-user';
import type { Response } from 'express';
import { RegisterDto } from './dto/register.dto';
import JwtAuthenticationGuard from './jwt.guard';
import { LocalAuthGuard } from './local-auth.guard';
import JwtRefreshGuard from './jwt-refresh.guard';
import { UsersService } from 'src/users/users.service';

@Controller('auths')
@SerializeOptions({
  strategy: 'excludeAll',
})
export class AuthsController {
  constructor(
    private readonly authService: AuthsService,
    private readonly userService: UsersService,
  ) {}

  @Post('register')
  signup(@Body() registerData: RegisterDto) {
    return this.authService.register(registerData);
  }

  @HttpCode(200)
  @UseGuards(LocalAuthGuard)
  @Post('log-in')
  async login(@Req() request: RequestWithUser) {
    const user = request.user;

    const accessTokenCookie = this.authService.getCookieWithJwtAccessToken(
      user.id!,
    );
    const refreshTokenCookie = this.authService.getCookieWithJwtRefreshToken(
      user.id!,
    );

    await this.userService.setCurrentRefreshToken(
      refreshTokenCookie.token,
      user.id!,
    );

    request.res.setHeader('Set-Cookie', [
      accessTokenCookie,
      refreshTokenCookie.cookie,
    ]);

    return user;
  }

  @UseGuards(JwtRefreshGuard)
  @Get('refresh')
  refresh(@Req() request: RequestWithUser) {
    const accessTokenCookie = this.authService.getCookieWithJwtAccessToken(
      request.user.id!,
    );

    request.res.setHeader('Set-Cookie', accessTokenCookie);

    return request.user;
  }

  @UseGuards(JwtAuthenticationGuard)
  @Post('log-out')
  @HttpCode(200)
  async logOut(@Req() request: RequestWithUser) {
    await this.userService.removeRefreshToken(request.user.id!);
    request.res.setHeader('Set-Cookie', this.authService.getCookiesForLogOut());
  }

  @UseGuards(JwtAuthenticationGuard)
  @Get()
  authenticate(@Req() request: RequestWithUser) {
    const user = request.user;
    user.password = '';
    return user;
  }
}
