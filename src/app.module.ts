import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PostsModule } from './posts/posts.module';
import { ConfigModule } from '@nestjs/config';
import { DatabaseModule } from './database/database.module';
import { UsersModule } from './users/users.module';
import { AuthsModule } from './auths/auths.module';
import * as Joi from 'joi';
import { APP_FILTER } from '@nestjs/core';
import { ExceptionLoggerFilter } from './shared/utils/exception';
import { CategoriesModule } from './categories/categories.module';
import { FilesModule } from './files/files.module';
import { ScheduleModule } from '@nestjs/schedule';
import { EmailModule } from './email/email.module';
import { EmailSchedulingModule } from './email-scheduling/email-scheduling.module';
import { ChatModule } from './chat/chat.module';
import { MessagesModule } from './messages/messages.module';
import { ChatGateway } from './chat/chat.gateway';

@Module({
  imports: [
    PostsModule,
    ScheduleModule.forRoot({}),
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: Joi.object({
        NODE_ENV: Joi.string()
          .valid('development', 'test', 'production')
          .default('development'),
        POSTGRES_HOST: Joi.string().required(),
        POSTGRES_PORT: Joi.number().required(),
        POSTGRES_USER: Joi.string().required(),
        POSTGRES_PASSWORD: Joi.string().required(),
        POSTGRES_DB: Joi.string().required(),
        PORT: Joi.number().optional(),
        JWT_ACCESS_TOKEN_SECRET: Joi.string().required(),
        JWT_ACCESS_TOKEN_EXPIRATION_TIME: Joi.string().required(),
        JWT_REFRESH_TOKEN_SECRET: Joi.string().required(),
        JWT_REFRESH_TOKEN_EXPIRATION_TIME: Joi.string().required(),
        AWS_REGION: Joi.string().required(),
        AWS_ACCESS_KEY_ID: Joi.string().required(),
        AWS_SECRET_ACCESS_KEY: Joi.string().required(),
        AWS_PUBLIC_BUCKET_NAME: Joi.string().required(),
        AWS_PRIVATE_BUCKET_NAME: Joi.string().required(),
        REDIS_HOST: Joi.string().required(),
        REDIS_PORT: Joi.number().required(),
        REDIS_TTL: Joi.number().default(120),
        REDIS_PASSWORD: Joi.string().optional(),
        REDIS_USERNAME: Joi.string().optional(),
        SMTP_HOST: Joi.string().when('NODE_ENV', {
          is: Joi.string().valid('development', 'test'),
          then: Joi.required(),
          otherwise: Joi.optional(),
        }),
        SMTP_PORT: Joi.string().when('NODE_ENV', {
          is: Joi.string().valid('development', 'test'),
          then: Joi.required(),
          otherwise: Joi.optional(),
        }),
        SMTP_USERNAME: Joi.string().when('NODE_ENV', {
          is: Joi.string().valid('development', 'test'),
          then: Joi.required(),
          otherwise: Joi.optional(),
        }),
        SMTP_PASSWORD: Joi.string().when('NODE_ENV', {
          is: Joi.string().valid('development', 'test'),
          then: Joi.required(),
          otherwise: Joi.optional(),
        }),
        SMTP_FROM: Joi.string().required(),
        EMAIL_HOST: Joi.string().optional(),
        EMAIL_PORT: Joi.number().optional(),
        EMAIL_SECURE: Joi.boolean().optional(),
        EMAIL_USER: Joi.string().optional(),
        EMAIL_PASSWORD: Joi.string().optional(),
        EMAIL_FROM: Joi.string().optional(),
      }),
    }),
    DatabaseModule,
    UsersModule,
    AuthsModule,
    CategoriesModule,
    FilesModule,
    EmailModule,
    EmailSchedulingModule,
    ChatModule,
    MessagesModule,
  ],
  controllers: [AppController],
  providers: [
    ChatGateway,
    AppService,
    {
      provide: APP_FILTER,
      useClass: ExceptionLoggerFilter,
    },
  ],
})
export class AppModule {}
