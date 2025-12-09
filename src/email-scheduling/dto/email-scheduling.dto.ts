import { IsDateString, IsNotEmpty, IsString } from "class-validator";

export class EmailScheduleDto {
    @IsString()
    recipient: string;

    @IsString()
    @IsNotEmpty()
    subject: string;

    @IsString()
    @IsNotEmpty()
    content: string;

    @IsDateString()
    date: string;
}