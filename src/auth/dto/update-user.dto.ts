import { PartialType } from '@nestjs/swagger';
import { CreateUserDto } from './create-user.dto';
import {
  IsOptional,
  IsString,
  IsBoolean,
  IsNumber,
  IsDate,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateUserDto extends PartialType(CreateUserDto) {
  @ApiPropertyOptional({
    description: 'Updated username',
    example: 'newusername',
  })
  @IsOptional()
  @IsString()
  username?: string;

  @ApiPropertyOptional({
    description: 'Updated full name',
    example: 'John Smith',
  })
  @IsOptional()
  @IsString()
  fullname?: string;

  @ApiPropertyOptional({
    description: 'Updated country',
    example: 'Canada',
  })
  @IsOptional()
  @IsString()
  country?: string;

  @ApiPropertyOptional({
    description: 'Updated user biography',
    example: 'Senior software engineer with 10+ years experience',
  })
  @IsOptional()
  @IsString()
  userBio?: string;

  @ApiPropertyOptional({
    description: 'Updated phone number',
    example: '+1987654321',
  })
  @IsOptional()
  @IsString()
  phoneNumber?: string;

  @ApiPropertyOptional({
    description: 'Account activation status (Admin only)',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  isAccountActive?: boolean;

  @ApiPropertyOptional({
    description: 'Updated country code',
    example: 'CA',
  })
  @IsOptional()
  @IsString()
  countryCode?: string;

  @ApiPropertyOptional({
    description: 'Failed login attempts count (Admin only)',
    example: 0,
  })
  @IsOptional()
  @IsNumber()
  failedLoginAttempts?: number;

  @ApiPropertyOptional({
    description: 'Account lock expiration date (Admin only)',
    example: '2024-12-31T23:59:59.999Z',
  })
  @IsOptional()
  @IsDate()
  accountLockedUntil?: Date;

  @ApiPropertyOptional({
    description: 'Email verification status (Admin only)',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  emailVerified?: boolean;

  @ApiPropertyOptional({
    description: 'Phone number verification status (Admin only)',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  phoneNoVerified?: boolean;

  @ApiPropertyOptional({
    description: 'Two-factor authentication status (Admin only)',
    example: true,
  })
  @IsOptional()
  @IsBoolean()
  is2FaEnabled?: boolean;
}
