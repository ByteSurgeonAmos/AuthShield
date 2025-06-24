import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';

@Injectable()
export class SmsService {
  private readonly tiaraApiUrl = 'https://api.tiara.tech/rest/v1/sms/send';
  private readonly apiToken: string;

  constructor(private config: ConfigService) {
    this.apiToken = this.config.get<string>('TIARA_API_TOKEN');

    if (!this.apiToken) {
      console.warn(
        'Tiara API token not configured. SMS functionality will be disabled.',
      );
    }
  }

  async sendSms(to: string, message: string): Promise<any> {
    if (!this.apiToken) {
      throw new HttpException(
        {
          status: HttpStatus.SERVICE_UNAVAILABLE,
          error:
            'SMS service not configured. Please check TIARA_API_TOKEN environment variable.',
        },
        HttpStatus.SERVICE_UNAVAILABLE,
      );
    }

    try {
      const response = await axios.post(
        this.tiaraApiUrl,
        {
          recipients: [to],
          message: message,
          sender: this.config.get<string>('SMS_SENDER_ID') || 'xmobit',
        },
        {
          headers: {
            Authorization: `Bearer ${this.apiToken}`,
            'Content-Type': 'application/json',
          },
        },
      );

      console.log('SMS sent successfully:', response.data);
      return response.data;
    } catch (error) {
      console.error(
        'SMS sending failed:',
        error.response?.data || error.message,
      );
      throw new HttpException(
        {
          status: HttpStatus.BAD_REQUEST,
          error: 'Failed to send SMS',
          details: error.response?.data || error.message,
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
