import { IsString, MinLength, IsOptional, IsNotEmpty } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CompleteProfileDto {
  @ApiProperty({
    description: 'Unique username (minimum 3 characters)',
    example: 'johndoe',
    minLength: 3,
  })
  @IsString()
  @MinLength(3)
  @IsNotEmpty()
  username: string;

  @ApiPropertyOptional({
    description: 'User phone number with country code',
    example: '+1234567890',
  })
  @IsString()
  @IsOptional()
  phoneNumber?: string;

  @ApiPropertyOptional({
    description: 'User country',
    example: 'United States',
  })
  @IsString()
  @IsOptional()
  country?: string;

  @ApiPropertyOptional({
    description: 'Country code (ISO 3166-1 alpha-2)',
    example: 'US',
  })
  @IsString()
  @IsOptional()
  countryCode?: string;

  @ApiPropertyOptional({
    description: 'User biography or description',
    example: 'Software developer passionate about technology',
  })
  @IsString()
  @IsOptional()
  userBio?: string;
}
