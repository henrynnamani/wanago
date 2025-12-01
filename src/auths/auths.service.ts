import {
  BadRequestException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { UsersService } from 'src/users/users.service';
import * as bcrypt from 'bcryptjs';
import { RegisterDto } from './dto/register.dto';
import { PostgresError } from 'src/database/postgresError.enum';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthsService {
  constructor(
    private readonly usersService: UsersService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async registerUser(data: RegisterDto) {
    const hashedPassword = await bcrypt.hash(data.password, 10);
    try {
      const record = await this.usersService.create({
        ...data,
        password: hashedPassword,
      });

      return record;
    } catch (err) {
      console.log(err);
      if (err?.code === PostgresError?.UniqueViolation) {
        throw new HttpException(
          'User with that email already exist',
          HttpStatus.BAD_REQUEST,
        );
      }
      throw new HttpException(
        'Something went wrong',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }
  }

  async getAuthenticatedUser(email: string, password: string) {
    try {
      const user = await this.usersService.getByEmail(email);

      await this.verifyPassword(password, user.password);

      return user;
    } catch (err) {
      throw new BadRequestException('Wrong credential provided');
    }
  }

  async verifyPassword(password: string, hashedPassword: string) {
    const isPasswordMatching = await bcrypt.compare(password, hashedPassword);

    if (!isPasswordMatching) {
      throw new BadRequestException('Wrong credential provided');
    }
  }

  async getJwtTokenWithCookie(userId) {
    const payload = { userId };
    const token = this.jwtService.sign(
      payload,
      this.configService.get('JWT_SECRET'),
    );
    return `Authorization=${token}; HttpOnly;Path=/;Max-Age=${this.configService.get('JWT_EXPIRATION_TIME')}`;
  }

  async getCookieForLogout() {
    return `Authentication=;HttpOnly;path=/;Max-Age=0;`;
  }
}
