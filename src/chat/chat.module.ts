import { Module } from '@nestjs/common';
import { ChatService } from './chat.service';
import { AuthsModule } from 'src/auths/auths.module';
import { ChatGateway } from './chat.gateway';
import { MessagesModule } from 'src/messages/messages.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Message } from 'src/messages/model/message.entity';

@Module({
  imports: [AuthsModule, MessagesModule, TypeOrmModule.forFeature([Message])],
  providers: [ChatService],
  exports: [ChatService]
})
export class ChatModule {}
