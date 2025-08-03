import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { formatPhoneNumber } from '../common/phone-utils';

@Injectable()
export class MockSmsService {
  constructor(private config: ConfigService) {}

  async sendSms(to: string, message: string): Promise<any> {
    const defaultCountryCode =
      this.config.get<string>('DEFAULT_COUNTRY_CODE') || '254';
    const phoneResult = formatPhoneNumber(
      to,
      undefined,
      undefined,
      defaultCountryCode,
    );

    return {
      success: true,
      messageId: `mock_${Date.now()}`,
      recipient: phoneResult.formatted,
      timestamp: new Date().toISOString(),
    };
  }
}
