import { IsString, MinLength, MaxLength, IsNotEmpty } from 'class-validator';
export class CreateUserDto {
  @IsString()
  @MinLength(3)
  @IsNotEmpty()
  email: string;

  @IsString()
  @MinLength(6)
  @IsNotEmpty()
  password: string;

  @IsString()
  @MinLength(3)
  @IsNotEmpty()
  username: string;
}
