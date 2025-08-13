import { Injectable, HttpException, HttpStatus } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';
import { MockSmsService } from './mock-sms.service';
import { formatPhoneNumber } from '../common/phone-utils';

@Injectable()
export class SmsService {
  private readonly infobipApiUrl =
    'https://api.infobip.com/sms/2/text/advanced';
  private readonly apiToken: string;
  private readonly mockSmsService: MockSmsService;

  constructor(private config: ConfigService) {
    this.apiToken = this.config.get<string>('INFOBIP_API_TOKEN');
    this.mockSmsService = new MockSmsService(config);

    if (!this.apiToken) {
      console.warn(
        '⚠️  Infobip API token not configured. Using mock SMS service for development.',
      );
      console.warn(
        'Set INFOBIP_API_TOKEN environment variable to enable real SMS functionality.',
      );
    }
  }

  async sendSms(
    to: string,
    message: string,
    countryCode?: string,
  ): Promise<any> {
    if (!this.apiToken) {
      return this.mockSmsService.sendSms(to, message);
    }

    const defaultCountryCode =
      this.config.get<string>('DEFAULT_COUNTRY_CODE') || '254';
    const phoneResult = formatPhoneNumber(
      to,
      countryCode,
      undefined,
      defaultCountryCode,
    );

    if (!phoneResult.isValid) {
      throw new HttpException(
        {
          status: HttpStatus.BAD_REQUEST,
          error:
            'Invalid phone number format. Please provide a valid phone number.',
        },
        HttpStatus.BAD_REQUEST,
      );
    }

    const senderID = this.config.get<string>('SMS_SENDER_ID') || 'XMOBIT';

    // Infobip API payload format
    const requestPayload = {
      messages: [
        {
          destinations: [
            {
              to: phoneResult.formatted,
            },
          ],
          from: senderID,
          text: message,
        },
      ],
    };

    try {
      const response = await axios.post(this.infobipApiUrl, requestPayload, {
        headers: {
          Authorization: `App ${this.apiToken}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        timeout: 15000,
      });

      return response.data;
    } catch (error) {
      console.error('❌ SMS sending failed - Full error details:');
      console.error('Error message:', error.message);
      console.error('Error response status:', error.response?.status);
      console.error('Error response data:', error.response?.data);

      let errorMessage = 'Failed to send SMS';
      let errorDetails = error.message;

      if (error.response) {
        const status = error.response.status;
        const data = error.response.data;

        switch (status) {
          case 401:
            errorMessage =
              'SMS service authentication failed. Please check INFOBIP_API_TOKEN.';
            errorDetails = 'The API token is invalid or has expired.';
            break;
          case 403:
            errorMessage =
              'SMS service access forbidden. Check API permissions and endpoint.';
            errorDetails = `Access denied. This could be due to:
1. Invalid API token or expired token
2. API endpoint changed (currently using: ${this.infobipApiUrl})
3. Account doesn't have SMS sending permissions
4. Wrong request format for the API
5. IP address not whitelisted (if applicable)

Please verify:
- Your INFOBIP_API_TOKEN is correct and active
- The API endpoint URL is correct
- Your Infobip account has SMS permissions
- Contact Infobip support if the issue persists`;
            break;
          case 400:
            errorMessage = 'Invalid SMS request format or parameters.';
            if (data?.requestError?.serviceException?.text) {
              errorDetails = data.requestError.serviceException.text;
            } else if (data?.requestError?.serviceException?.messageId) {
              errorDetails = `Request error: ${data.requestError.serviceException.messageId}`;
            } else {
              errorDetails = `Bad request. The API might expect a different request format. 
Current payload: ${JSON.stringify(requestPayload, null, 2)}`;
            }
            break;
          case 429:
            errorMessage =
              'SMS service rate limit exceeded. Please try again later.';
            break;
          case 500:
            errorMessage =
              'SMS service internal error. Please try again later.';
            break;
          default:
            errorMessage = `SMS service error (${status})`;
        }

        errorDetails = data || error.message;
      }

      throw new HttpException(
        {
          status: HttpStatus.BAD_REQUEST,
          error: errorMessage,
          details: errorDetails,
        },
        HttpStatus.BAD_REQUEST,
      );
    }
  }
}
