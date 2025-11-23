import { Strategy } from 'passport-local';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthsService } from './auths.service';
import { User } from 'src/users/user.entity';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authenticationService: AuthsService) {
    super({
      usernameField: 'email',
    });
  }

  async validate(email: string, password: string): Promise<User> {
    console.log(email, password);
    const result = await this.authenticationService.getAuthenticatedUser(
      email,
      password,
    );

    if (!result) {
      throw new UnauthorizedException();
    }

    return result;
  }
}
