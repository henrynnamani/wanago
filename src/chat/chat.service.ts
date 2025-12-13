import { Injectable } from '@nestjs/common';
import { WsException } from '@nestjs/websockets';
import { parse } from 'cookie';
import { Socket } from 'socket.io';
import { AuthsService } from 'src/auths/auths.service';

@Injectable()
export class ChatService {
  constructor(private readonly authsService: AuthsService) {}

  async getUserFromSocket(socket: Socket) {
    const cookie = socket.handshake.headers.cookie;

    const { Authentication: authentication } = parse(cookie as string);

    const user = await this.authsService.getUserFromAuthenticationToken(
      authentication as string,
    );

    if (!user) {
      throw new WsException('Invalid Credentials');
    }

    return user;
  }
}
