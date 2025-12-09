import { Module } from '@nestjs/common';
import { MessagesService } from './messages.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Message } from './model/message.entity';
import { AuthsModule } from 'src/auths/auths.module';

@Module({
  imports: [TypeOrmModule.forFeature([Message]), AuthsModule],
  providers: [MessagesService],
  exports: [MessagesService],
})
export class MessagesModule {}
