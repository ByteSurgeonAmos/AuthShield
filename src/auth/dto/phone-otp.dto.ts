import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsPhoneNumber } from 'class-validator';

export class SendPhoneOTPDto {
  @ApiProperty({
    description: 'Phone number to send OTP to',
    example: '+1234567890',
    type: String,
  })
  @IsString()
  @IsNotEmpty()
  phoneNumber: string;

  @ApiProperty({
    description: 'Country code for the phone number',
    example: '254',
    type: String,
  })
  @IsString()
  @IsNotEmpty()
  countryCode: string;
}

export class VerifyPhoneOTPDto {
  @ApiProperty({
    description: 'Phone number',
    example: '+1234567890',
    type: String,
  })
  @IsString()
  @IsNotEmpty()
  phoneNumber: string;

  @ApiProperty({
    description: 'OTP code received via SMS',
    example: '123456',
    type: String,
  })
  @IsString()
  @IsNotEmpty()
  otpCode: string;

  @ApiProperty({
    description: 'Country code for the phone number',
    example: '254',
    type: String,
    required: false,
  })
  @IsString()
  countryCode?: string;
}
