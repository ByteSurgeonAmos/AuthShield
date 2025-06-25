import { IsString, IsNotEmpty, MinLength, MaxLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class SetSecurityQuestionDto {
  @ApiProperty({
    description: 'Security question (max 500 characters)',
    example: 'What was the name of your first pet?',
    maxLength: 500,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(500)
  question: string;

  @ApiProperty({
    description: 'Answer to the security question (3-100 characters)',
    example: 'Fluffy',
    minLength: 3,
    maxLength: 100,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(100)
  answer: string;
}

export class VerifySecurityQuestionDto {
  @ApiProperty({
    description: 'Answer to verify the security question',
    example: 'Fluffy',
  })
  @IsString()
  @IsNotEmpty()
  answer: string;
}

export class UpdateSecurityQuestionDto {
  @ApiProperty({
    description: 'New security question (max 500 characters)',
    example: 'What city were you born in?',
    maxLength: 500,
  })
  @IsString()
  @IsNotEmpty()
  @MaxLength(500)
  newQuestion: string;

  @ApiProperty({
    description: 'Answer to the new security question (3-100 characters)',
    example: 'New York',
    minLength: 3,
    maxLength: 100,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(100)
  newAnswer: string;

  @ApiProperty({
    description: 'Current answer for verification',
    example: 'Fluffy',
  })
  @IsString()
  @IsNotEmpty()
  currentAnswer: string;
}
