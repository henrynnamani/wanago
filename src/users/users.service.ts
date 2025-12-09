import {
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
  RequestTimeoutException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './model/user.entity';
import { DataSource, Repository } from 'typeorm';
import { CreateUserDto } from './dto/user.dto';
import { Address } from './model/address.entity';
import { FilesService } from 'src/files/files.service';
import { PrivateFileService } from 'src/files/private-file.service';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepository: Repository<User>,
    @InjectRepository(Address)
    private readonly addressRepository: Repository<Address>,
    private readonly filesService: FilesService,
    private readonly privateFileService: PrivateFileService,
    private datasource: DataSource,
  ) {}

  async setCurrentHashedRefreshToken(refreshToken: string, userId: string) {
    const currentHashedRefreshToken = await bcrypt.hash(refreshToken, 10);

    await this.usersRepository.update(userId, {
      currentHashedRefreshToken,
    });
  }

  async getByEmail(email: string) {
    try {
      const user = await this.usersRepository.findOne({
        where: { email },
        select: ['id', 'email', 'name', 'password'],
      });

      if (user) {
        return user;
      }

      throw new HttpException(
        'User with this email does not exist',
        HttpStatus.NOT_FOUND,
      );
    } catch (err) {
      throw new RequestTimeoutException(err);
    }
  }

  async getUserIfRefreshTokenMatches(refreshToken: string, userId: string) {
    const user = await this.getById(userId);

    const isRefreshTokenMatching = await bcrypt.compare(
      refreshToken,
      user.currentHashedRefreshToken!,
    );

    if (isRefreshTokenMatching) {
      return user;
    }
  }

  async removeRefreshToken(userId: string) {
    return this.usersRepository.update(userId, {
      currentHashedRefreshToken: undefined,
    });
  }

  async getById(id: string) {
    const user = await this.usersRepository.findOneBy({ id });
    if (user) {
      return user;
    }
    throw new NotFoundException('User not found');
  }

  async create(userData: CreateUserDto) {
    const newUser = this.usersRepository.create(userData);
    await this.usersRepository.save(newUser);
    return newUser;
  }

  async getAllAddressesWithUser() {
    return this.addressRepository.find({ relations: ['user'] });
  }

  async addAvatar(userId: string, imageBuffer: Buffer, filename: string) {
    const avatar = await this.filesService.uploadPublicFile(
      imageBuffer,
      filename,
    );
    const user = await this.getById(userId);
    await this.usersRepository.update(userId, {
      ...user,
      avatar,
    });
    return avatar;
  }

  async deleteAvatar(userId: string) {
    return await this.datasource.transaction(async (manager) => {
      const user = await manager.findOne(User, {
        where: { id: userId },
        relations: ['avatar'],
      });

      if (user?.avatar) return;

      const fileId = user?.avatar?.id;

      await manager.update(User, userId, {
        avatar: undefined,
      });

      await this.filesService.deletePublicFile(fileId!);
    });
  }

  async addPrivateFile(userId: string, imageBuffer: Buffer, filename: string) {
    return this.privateFileService.uploadPrivateFile(
      imageBuffer,
      userId,
      filename,
    );
  }
}
