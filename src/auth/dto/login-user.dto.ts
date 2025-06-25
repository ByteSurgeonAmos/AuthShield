import { IsEmail, IsNotEmpty, Length } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginUserDto {
  @ApiProperty({
    description: 'User email address',
    example: 'john.doe@example.com',
    format: 'email',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    description: 'User password (6-20 characters)',
    example: 'securePassword123',
    minLength: 6,
    maxLength: 20,
  })
  @IsNotEmpty()
  @Length(6, 20)
  password: string;
}
