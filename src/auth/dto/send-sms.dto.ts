import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty, IsUUID } from 'class-validator';

export class SendSmsDto {
  @ApiProperty({
    description: 'User ID to send SMS to',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
    type: String,
  })
  @IsString()
  @IsNotEmpty()
  @IsUUID()
  userId: string;

  @ApiProperty({
    description: 'SMS message content',
    example: 'Your transaction has been completed successfully.',
    type: String,
  })
  @IsString()
  @IsNotEmpty()
  message: string;
}
