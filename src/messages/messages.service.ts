import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthsService } from 'src/auths/auths.service';
import { Message } from './model/message.entity';
import { Repository } from 'typeorm';
import { User } from 'src/users/model/user.entity';

@Injectable()
export class MessagesService {
  constructor(
    private readonly authsService: AuthsService,
    @InjectRepository(Message)
    private readonly messageRepository: Repository<Message>,
  ) {}

  async saveMessage(content: string, author: User) {
    const record = this.messageRepository.create({
      content,
      author,
    });

    await this.messageRepository.save(record);

    return record;
  }

  async getAllMessage() {
    return this.messageRepository.find({
      relations: ['author'],
    });
  }
}
