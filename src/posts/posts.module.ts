import { Module } from '@nestjs/common';
import { PostsController } from './posts.controller';
import { PostsService } from './posts.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Post } from './model/post.entity';
import { CacheModule } from '@nestjs/cache-manager';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { redisStore } from 'cache-manager-redis-yet';
import { config } from 'process';
import { PostsResolver } from './post.resolver';
import { PrismaModule } from 'src/prisma/prisma.module';

@Module({
  imports: [
    PrismaModule,
    TypeOrmModule.forFeature([Post]),
    CacheModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        store: await redisStore({
          socket: {
            host: configService.get('REDIS_HOST', 'localhost'),
            port: Number(configService.get('REDIS_PORT', 6379)),
          },
          ttl: Number(configService.get('REDIS_TTL')) * 1000,
        }),
      }),
    }),
  ],
  controllers: [PostsController],
  providers: [PostsService, PostsResolver],
})
export class PostsModule {}
