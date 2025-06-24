import { IsString, IsNotEmpty, MinLength, MaxLength } from 'class-validator';

export class SetSecurityQuestionDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(500)
  question: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(100)
  answer: string;
}

export class VerifySecurityQuestionDto {
  @IsString()
  @IsNotEmpty()
  answer: string;
}

export class UpdateSecurityQuestionDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(500)
  newQuestion: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(100)
  newAnswer: string;

  @IsString()
  @IsNotEmpty()
  currentAnswer: string;
}
