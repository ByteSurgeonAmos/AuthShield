import { PartialType } from '@nestjs/mapped-types';
import { CreateUserDto } from './create-user.dto';
import {
  IsOptional,
  IsString,
  IsBoolean,
  IsNumber,
  IsDate,
} from 'class-validator';

export class UpdateUserDto extends PartialType(CreateUserDto) {
  @IsOptional()
  @IsString()
  username?: string;

  @IsOptional()
  @IsString()
  fullname?: string;

  @IsOptional()
  @IsString()
  country?: string;

  @IsOptional()
  @IsString()
  userBio?: string;

  @IsOptional()
  @IsString()
  phoneNumber?: string;

  @IsOptional()
  @IsBoolean()
  isAccountActive?: boolean;

  @IsOptional()
  @IsString()
  countryCode?: string;

  @IsOptional()
  @IsNumber()
  failedLoginAttempts?: number;

  @IsOptional()
  @IsDate()
  accountLockedUntil?: Date;

  @IsOptional()
  @IsBoolean()
  emailVerified?: boolean;

  @IsOptional()
  @IsBoolean()
  phoneNoVerified?: boolean;

  @IsOptional()
  @IsBoolean()
  is2FaEnabled?: boolean;
}
