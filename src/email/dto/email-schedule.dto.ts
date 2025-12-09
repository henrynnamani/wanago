import { IsDateString, IsNotEmpty, IsString } from "class-validator";

export class EmailScheduleDto {
  @IsDateString()
  @IsNotEmpty()
  date: Date;

  @IsString()
  @IsNotEmpty()
  recipient: string;

  @IsString()
  @IsNotEmpty()
  subject: string;

  @IsString()
  @IsNotEmpty()
  content: string;

  @IsString()
  @IsNotEmpty()
  html: string;

  @IsString()
  @IsNotEmpty()
  cc: string;

  @IsString()
  @IsNotEmpty()
  bcc: string;
}