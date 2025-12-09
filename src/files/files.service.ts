import { Injectable, RequestTimeoutException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { v4 as uuid } from 'uuid';
import { PublicFile } from './model/publicfile.entity';
import { Repository } from 'typeorm';
import { ConfigService } from '@nestjs/config';
import {
  DeleteObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';

@Injectable()
export class FilesService {
  private s3client: S3Client;
  constructor(
    @InjectRepository(PublicFile)
    private readonly fileRepository: Repository<PublicFile>,
    private readonly configService: ConfigService,
  ) {
    this.s3client = new S3Client({
      region: configService.get('AWS_REGION'),
      credentials: {
        accessKeyId: configService.get('AWS_ACCESS_KEY_ID')!,
        secretAccessKey: configService.get('AWS_SECRET_ACCESS_KEY')!,
      },
    });
  }

  async deletePublicFile(fileId: string) {
    const file = await this.fileRepository.findOneBy({ id: fileId });

    await this.s3client.send(
      new DeleteObjectCommand({
        Bucket: this.configService.get('AWS_PUBLIC_BUCKET_NAME'),
        Key: file?.key,
      }),
    );

    await this.fileRepository.delete(fileId);
  }

  async uploadPublicFile(dataBuffer: Buffer, filename: string) {
    const key = `${uuid()}-${filename}`;

    console.log(this.configService.get('AWS_PUBLIC_BUCKET_NAME'));

    try {
      await this.s3client.send(
        new PutObjectCommand({
          Bucket: this.configService.get('AWS_PUBLIC_BUCKET_NAME'),
          Key: key,
          Body: dataBuffer,
        }),
      );

      const url = `https://${this.configService.get('AWS_PUBLIC_BUCKET_NAME')}.s3.${this.configService.get('AWS_REGION')}.amazonaws.com/${key}`;

      const newFile = this.fileRepository.create({ key, url });

      await this.fileRepository.save(newFile);

      return newFile;
    } catch (err) {
      console.log(err);
      throw new RequestTimeoutException(err);
    }
  }
}
