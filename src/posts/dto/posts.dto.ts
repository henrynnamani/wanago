import { IsNotEmpty, IsNumber, IsString, MinLength } from 'class-validator';

export class CreatePostDto {
  @IsString()
  content: string;

  @IsString()
  @MinLength(6)
  title: string;
}

export class UpdatePostDto {
  @IsString()
  id: string;

  @IsString()
  content: string;

  @IsString()
  title: string;
}
