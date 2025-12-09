import { Injectable, RequestTimeoutException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { PrivateFile } from './model/privatefile.entity';
import { Repository } from 'typeorm';
import { PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { ConfigService } from '@nestjs/config';
import { v4 as uuid } from 'uuid';

@Injectable()
export class PrivateFileService {
  private s3Client: S3Client;
  constructor(
    @InjectRepository(PrivateFile)
    private readonly privateFileRepository: Repository<PrivateFile>,
    private configService: ConfigService,
  ) {
    this.s3Client = new S3Client({
      region: configService.get('AWS_REGION'),
      credentials: {
        accessKeyId: configService.get('AWS_ACCESS_KEY_ID')!,
        secretAccessKey: configService.get('AWS_SECRET_ACCESS_KEY')!,
      },
    });
  }

  async uploadPrivateFile(
    dataBuffer: Buffer,
    ownerId: string,
    filename: string,
  ) {
    try {
      const key = `${uuid()}-${filename}`;

      await this.s3Client.send(
        new PutObjectCommand({
          Bucket: this.configService.get('AWS_PRIVATE_BUCKET_NAME'),
          Key: key,
          Body: dataBuffer,
        }),
      );

      const newFile = this.privateFileRepository.create({
        key,
        owner: { id: ownerId },
      });

      await this.privateFileRepository.save(newFile);

      return newFile;
    } catch (err) {
      console.log(err);
      throw new RequestTimeoutException(err);
    }
  }
}
