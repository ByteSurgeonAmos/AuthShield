import { IsString, IsNotEmpty } from 'class-validator';

export class Verify2FALoginDto {
  @IsString()
  @IsNotEmpty()
  temporaryToken: string;

  @IsString()
  @IsNotEmpty()
  twoFactorCode: string;
}
