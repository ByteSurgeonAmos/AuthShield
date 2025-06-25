import { IsEnum, IsOptional, IsString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum TwoFactorMethod {
  EMAIL = 'email',
  PHONE = 'phone',
  AUTHENTICATOR = 'authenticator',
}

export class Setup2FADto {
  @ApiProperty({
    description: 'Two-factor authentication method',
    enum: TwoFactorMethod,
    example: TwoFactorMethod.EMAIL,
  })
  @IsEnum(TwoFactorMethod)
  method: TwoFactorMethod;

  @ApiPropertyOptional({
    description: 'Verification token (used during setup verification)',
    example: '123456',
  })
  @IsOptional()
  @IsString()
  token?: string;
}

export class Verify2FADto {
  @ApiProperty({
    description: 'Two-factor authentication token/code',
    example: '123456',
  })
  @IsString()
  token: string;

  @ApiProperty({
    description: 'User ID',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  @IsString()
  userId: string;
}

export class Disable2FADto {
  @ApiProperty({
    description: 'User ID',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  @IsString()
  userId: string;

  @ApiProperty({
    description: 'Current user password for verification',
    example: 'currentPassword123',
  })
  @IsString()
  currentPassword: string;

  @ApiPropertyOptional({
    description: 'Additional verification token if required',
    example: '123456',
  })
  @IsOptional()
  @IsString()
  verificationToken?: string;
}
