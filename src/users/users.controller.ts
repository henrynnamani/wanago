import {
  Controller,
  Post,
  Req,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { LoggedInUser } from 'src/auths/decorator/current-user.decorator';
import { User } from './model/user.entity';
import { FileInterceptor } from '@nestjs/platform-express';
import { Express } from 'express';
import { FilesService } from 'src/files/files.service';
import { JwtAuthGuard } from 'src/auths/guard/jwt.guard';
import { UsersService } from './users.service';

@Controller('users')
export class UsersController {
  constructor(
    private readonly filesService: FilesService,
    private readonly usersService: UsersService,
  ) {}
  @Post('avatar')
  @UseGuards(JwtAuthGuard)
  @UseInterceptors(FileInterceptor('file'))
  async addAvatar(
    @LoggedInUser() user: User,
    @UploadedFile() file: Express.Multer.File,
  ) {
    return this.filesService.uploadPublicFile(file.buffer, file.originalname);
  }

  @Post('files')
  @UseGuards(JwtAuthGuard)
  @UseInterceptors(FileInterceptor('file'))
  async addPrivateFile(
    @LoggedInUser() user: User,
    @UploadedFile() file: Express.Multer.File,
  ) {
    return this.usersService.addPrivateFile(
      user.id,
      file.buffer,
      file.originalname,
    );
  }
}
