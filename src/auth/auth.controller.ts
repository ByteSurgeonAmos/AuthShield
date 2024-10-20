import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  Request,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { AuthGuard } from './guards/jwt-auth.guard';

@Controller('auth')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @UseGuards(AuthGuard)
  @Get()
  findAll() {
    return this.usersService.findAll();
  }
  @Get('verify')
  async verifyEmail(@Query('token') token: string) {
    return await this.usersService.verifyEmail(token);
  }
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.usersService.findOne(+id);
  }

  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(+id, updateUserDto);
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.usersService.remove(+id);
  }
  @Post('/login')
  login(@Body() loginDto: LoginUserDto) {
    return this.usersService.login(loginDto);
  }

  @Post('resend-verification')
  async resendVerificationToken(@Body('email') email: string) {
    return await this.usersService.resendVerificationToken(email);
  }
  @UseGuards(AuthGuard)
  @Post('send-sms')
  async sendSMSVerification(
    @Request() req: any,
    @Body('phone') phoneNumber: string,
  ) {
    return await this.usersService.sendOTP(phoneNumber, req.user.userId);
  }

  @UseGuards(AuthGuard)
  @Post('verify-sms')
  async VerifySMSVerification(@Request() req: any, @Body('otp') otp: string) {
    return await this.usersService.verifyOTP(otp, req.user.userId);
  }
}
