import {
  Body,
  Controller,
  HttpCode,
  Post,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthsService } from './auths.service';
import { RegisterDto } from './dto/register.dto';
import { RequestWithUser } from './interface/requestWithUser.interface';
import { LocalAuthGuard } from './guard/auth.guard';
import { LoggedInUser } from './decorator/current-user.decorator';
import { User } from 'src/users/model/user.entity';
import { Response } from 'express';
import { JwtAuthGuard } from './guard/jwt.guard';

@Controller('auths')
export class AuthsController {
  constructor(private readonly authsService: AuthsService) {}

  @Post('register')
  registerUser(@Body() registerData: RegisterDto) {
    return this.authsService.registerUser(registerData);
  }

  @HttpCode(200)
  @UseGuards(LocalAuthGuard)
  @Post('log-in')
  async login(@LoggedInUser() user: User, @Res() response: Response) {
    const cookie = await this.authsService.getJwtTokenWithCookie(user.id);

    response.setHeader('Set-Cookie', cookie);
    return response.send(user);
  }

  @UseGuards(JwtAuthGuard)
  @Post('log-out')
  async logOut(@LoggedInUser() user: User, @Res() response: Response) {
    response.setHeader(
      'Set-Cookie',
      await this.authsService.getCookieForLogout(),
    );
    return response.send(user);
  }
}
