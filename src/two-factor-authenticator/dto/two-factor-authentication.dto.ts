import { IsNotEmpty, IsNumber, IsString } from "class-validator";

export class TwoFactorAuthenticationCodeDto {
    @IsString()
    @IsNotEmpty()
    twoFactorAuthenticationCode: string;
}