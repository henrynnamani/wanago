import { Module } from '@nestjs/common';
import { FilesService } from './files.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PublicFile } from './model/publicfile.entity';
import { PrivateFile } from './model/privatefile.entity';
import { PrivateFileService } from './private-file.service';

@Module({
  imports: [TypeOrmModule.forFeature([PublicFile, PrivateFile])],
  providers: [FilesService, PrivateFileService],
  exports: [FilesService, PrivateFileService],
})
export class FilesModule {}
