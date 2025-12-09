import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  SerializeOptions,
  UseGuards,
} from '@nestjs/common';
import { AuthsService } from './auths.service';
import { RegisterDto } from './dto/register.dto';
import { RequestWithUser } from './interface/requestWithUser.interface';
import { LocalAuthGuard } from './guard/auth.guard';
import { LoggedInUser } from './decorator/current-user.decorator';
import { User } from 'src/users/model/user.entity';
import { Request, Response } from 'express';
import { JwtAuthGuard } from './guard/jwt.guard';
import { request } from 'http';
import { UsersService } from 'src/users/users.service';
import JwtRefreshGuard from './guard/refresh.guard';

@SerializeOptions({
  strategy: 'exposeAll',
})
@Controller('auths')
export class AuthsController {
  constructor(
    private readonly authsService: AuthsService,
    private readonly usersService: UsersService,
  ) {}

  @Post('register')
  registerUser(@Body() registerData: RegisterDto) {
    return this.authsService.registerUser(registerData);
  }

  @HttpCode(200)
  @UseGuards(LocalAuthGuard)
  @Post('log-in')
  async login(@LoggedInUser() user: User, @Req() request: Request) {
    const accessTokenCookie =
      await this.authsService.getCookieWithJwtAccessToken(user.id);
    const refreshTokenCookie =
      await this.authsService.getCookieWithJwtRefreshToken(user.id);

    await this.usersService.setCurrentHashedRefreshToken(
      refreshTokenCookie,
      user.id,
    );


    request.res?.setHeader('Set-Cookie', [
      accessTokenCookie,
      refreshTokenCookie,
    ]);
    return user;
  }

  @UseGuards(JwtRefreshGuard)
  @Get('refresh')
  async refresh(@LoggedInUser('id') userId: string, @Req() request: Request) {
    const accessTokenCookie =
      await this.authsService.getCookieWithJwtAccessToken(userId);

    request?.res?.setHeader('Set-Cookie', accessTokenCookie);
    return request.user;
  }

  @UseGuards(JwtAuthGuard)
  @Post('log-out')
  async logOut(@LoggedInUser() user: User, @Req() request: Request) {
    await this.usersService.removeRefreshToken(user.id);
    request.res?.setHeader(
      'Set-Cookie',
      await this.authsService.getCookieForLogout(),
    );
  }

  @UseGuards(JwtAuthGuard)
  @Get('me')
  authenticateUser(@LoggedInUser() user: User) {
    return user;
  }
}
