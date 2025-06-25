import { Controller, Post, Body } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBody } from '@nestjs/swagger';
import { SmsService } from './sms.service';

@ApiTags('SMS')
@Controller('sms')
export class SmsController {
  constructor(private readonly smsService: SmsService) {}

  @Post('send')
  @ApiOperation({
    summary: 'Send SMS',
    description: 'Send SMS message to a phone number',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        to: {
          type: 'string',
          description: 'Recipient phone number',
          example: '+1234567890',
        },
        message: {
          type: 'string',
          description: 'SMS message content',
          example: 'Your verification code is: 123456',
        },
      },
      required: ['to', 'message'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'SMS sent successfully',
    schema: {
      type: 'object',
      properties: {
        success: { type: 'boolean', example: true },
        messageId: { type: 'string', example: 'msg_123456' },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid phone number or message',
  })
  async sendSms(
    @Body('to') to: string,
    @Body('message') message: string,
  ): Promise<any> {
    return this.smsService.sendSms(to, message);
  }
}
