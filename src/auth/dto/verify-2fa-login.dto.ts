import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class Verify2FALoginDto {
  @ApiProperty({
    description: 'Temporary token received during initial login attempt',
    example: 'temp_token_abc123xyz',
  })
  @IsString()
  @IsNotEmpty()
  temporaryToken: string;

  @ApiProperty({
    description: 'Two-factor authentication code',
    example: '123456',
  })
  @IsString()
  @IsNotEmpty()
  twoFactorCode: string;
}
