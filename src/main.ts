import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import * as cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';
import { ExcludeNullInterceptor } from './shared/utils/excludeNull.interceptor';
import { config } from 'aws-sdk';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: true,
    credentials: true,
  });

  app.use(cookieParser());

  app.useGlobalPipes(new ValidationPipe());

  app.useGlobalInterceptors(new ExcludeNullInterceptor());

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
