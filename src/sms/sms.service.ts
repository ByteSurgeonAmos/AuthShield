import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as africastalking from 'africastalking';

@Injectable()
export class SmsService {
  private africastalking;

  constructor(private config: ConfigService) {
    this.africastalking = africastalking({
      apiKey: this.config.get<string>('AT_KEY'),
      username: this.config.get<string>('AT_USERNAME'),
    });
  }

  async sendSms(to: string, message: string): Promise<any> {
    const sms = this.africastalking.SMS;

    try {
      const response = await sms.send({
        to: [to],
        message: message,
        from: process.env.AT_SENDER_ID || undefined,
      });
      return response;
    } catch (error) {
      throw new HttpException(
        {
          status: HttpStatus.BAD_REQUEST,
          error: 'Failed to send SMS',
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
