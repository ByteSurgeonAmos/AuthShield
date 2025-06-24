import { IsEnum, IsOptional, IsString } from 'class-validator';

export enum TwoFactorMethod {
  EMAIL = 'email',
  PHONE = 'phone',
  AUTHENTICATOR = 'authenticator',
}

export class Setup2FADto {
  @IsEnum(TwoFactorMethod)
  method: TwoFactorMethod;

  @IsOptional()
  @IsString()
  token?: string; // For verifying the setup
}

export class Verify2FADto {
  @IsString()
  token: string;

  @IsString()
  userId: string;
}

export class Disable2FADto {
  @IsString()
  userId: string;

  @IsString()
  currentPassword: string;

  @IsOptional()
  @IsString()
  verificationToken?: string;
}
