import { Controller, Post, Body } from '@nestjs/common';
import { SmsService } from './sms.service';

@Controller('sms')
export class SmsController {
  constructor(private readonly smsService: SmsService) {}

  @Post('send')
  async sendSms(
    @Body('to') to: string,
    @Body('message') message: string,
  ): Promise<any> {
    return this.smsService.sendSms(to, message);
  }
}
