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

    console.log('🔧 MOCK SMS SERVICE - SMS would be sent to:');
    console.log('- Original:', to);
    console.log('- Formatted:', phoneResult.formatted);
    console.log('- Valid:', phoneResult.isValid);
    console.log('- Country Code:', phoneResult.countryCode);
    console.log('📱 Message:', message);
    console.log(
      '⚠️  This is a mock service. Set TIARA_API_TOKEN to use real SMS.',
    );

    return {
      success: true,
      messageId: `mock_${Date.now()}`,
      recipient: phoneResult.formatted,
      timestamp: new Date().toISOString(),
    };
  }
}
