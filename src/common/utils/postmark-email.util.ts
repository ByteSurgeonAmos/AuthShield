import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ServerClient, Models } from 'postmark';
import * as fs from 'fs';
import * as path from 'path';
import * as handlebars from 'handlebars';

export interface EmailOptions {
  to: string | string[];
  subject: string;
  htmlBody?: string;
  textBody?: string;
  from?: string;
  replyTo?: string;
  cc?: string | string[];
  bcc?: string | string[];
  tag?: string;
  trackOpens?: boolean;
  trackLinks?: Models.LinkTrackingOptions;
  metadata?: Record<string, string>;
  attachments?: Array<{
    name: string;
    content: string;
    contentType: string;
  }>;
}

@Injectable()
export class PostmarkEmailService {
  private client: ServerClient;
  private defaultFrom: string;

  constructor(private configService: ConfigService) {
    const serverToken = this.configService.get<string>('POSTMARK_SERVER_TOKEN');

    if (!serverToken) {
      throw new Error('POSTMARK_SERVER_TOKEN is not configured');
    }

    this.client = new ServerClient(serverToken);
    this.defaultFrom =
      this.configService.get<string>('NOTIFICATIONS_EMAIL') ||
      'no.reply@xmobit.com';
  }

  async sendEmail(
    options: EmailOptions,
  ): Promise<Models.MessageSendingResponse> {
    try {
      const message: Models.Message = {
        From: options.from || this.defaultFrom,
        To: Array.isArray(options.to) ? options.to.join(',') : options.to,
        Subject: options.subject,
        HtmlBody: options.htmlBody,
        TextBody: options.textBody,
        ReplyTo: options.replyTo,
        Cc: Array.isArray(options.cc) ? options.cc.join(',') : options.cc,
        Bcc: Array.isArray(options.bcc) ? options.bcc.join(',') : options.bcc,
        Tag: options.tag,
        TrackOpens: options.trackOpens,
        TrackLinks: options.trackLinks,
        Metadata: options.metadata,
        Attachments: options.attachments?.map((attachment) => ({
          Name: attachment.name,
          Content: attachment.content,
          ContentType: attachment.contentType,
          ContentID: attachment.name,
        })),
      };

      const response = await this.client.sendEmail(message);
      console.log('✅ Email sent successfully via Postmark:', {
        messageId: response.MessageID,
        to: options.to,
        subject: options.subject,
      });

      return response;
    } catch (error) {
      console.error('❌ Failed to send email via Postmark:', error);
      throw error;
    }
  }

  async sendBulkEmails(
    emails: EmailOptions[],
  ): Promise<Models.MessageSendingResponse[]> {
    try {
      const messages: Models.Message[] = emails.map((options) => ({
        From: options.from || this.defaultFrom,
        To: Array.isArray(options.to) ? options.to.join(',') : options.to,
        Subject: options.subject,
        HtmlBody: options.htmlBody,
        TextBody: options.textBody,
        ReplyTo: options.replyTo,
        Cc: Array.isArray(options.cc) ? options.cc.join(',') : options.cc,
        Bcc: Array.isArray(options.bcc) ? options.bcc.join(',') : options.bcc,
        Tag: options.tag,
        TrackOpens: options.trackOpens,
        TrackLinks: options.trackLinks,
        Metadata: options.metadata,
        Attachments: options.attachments?.map((attachment) => ({
          Name: attachment.name,
          Content: attachment.content,
          ContentType: attachment.contentType,
          ContentID: attachment.name,
        })),
      }));

      const responses = await this.client.sendEmailBatch(messages);
      console.log(
        `✅ ${responses.length} emails sent successfully via Postmark batch API`,
      );

      return responses;
    } catch (error) {
      console.error('❌ Failed to send bulk emails via Postmark:', error);
      throw error;
    }
  }

  async sendTemplatedEmail(
    templateIdOrAlias: string | number,
    templateModel: any,
    options: Omit<EmailOptions, 'htmlBody' | 'textBody'>,
  ): Promise<Models.MessageSendingResponse> {
    try {
      const message: Models.TemplatedMessage = {
        From: options.from || this.defaultFrom,
        To: Array.isArray(options.to) ? options.to.join(',') : options.to,
        TemplateId:
          typeof templateIdOrAlias === 'number' ? templateIdOrAlias : undefined,
        TemplateAlias:
          typeof templateIdOrAlias === 'string' ? templateIdOrAlias : undefined,
        TemplateModel: templateModel,
        ReplyTo: options.replyTo,
        Cc: Array.isArray(options.cc) ? options.cc.join(',') : options.cc,
        Bcc: Array.isArray(options.bcc) ? options.bcc.join(',') : options.bcc,
        Tag: options.tag,
        TrackOpens: options.trackOpens,
        TrackLinks: options.trackLinks,
        Metadata: options.metadata,
        Attachments: options.attachments?.map((attachment) => ({
          Name: attachment.name,
          Content: attachment.content,
          ContentType: attachment.contentType,
          ContentID: attachment.name,
        })),
      };

      const response = await this.client.sendEmailWithTemplate(message);
      console.log('✅ Templated email sent successfully via Postmark:', {
        messageId: response.MessageID,
        to: options.to,
        templateId: templateIdOrAlias,
      });

      return response;
    } catch (error) {
      console.error('❌ Failed to send templated email via Postmark:', error);
      throw error;
    }
  }

  async getDeliveryStats(): Promise<any> {
    try {
      return await this.client.getDeliveryStatistics();
    } catch (error) {
      console.error('❌ Failed to get delivery stats from Postmark:', error);
      throw error;
    }
  }

  async getServerInfo(): Promise<any> {
    try {
      return await this.client.getServer();
    } catch (error) {
      console.error('❌ Failed to get server info from Postmark:', error);
      throw error;
    }
  }

  private loadTemplate(templateName: string, templateData: any): string {
    const templatePath = path.join(
      __dirname,
      '..',
      '..',
      'templates',
      templateName,
    );
    const source = fs.readFileSync(templatePath, 'utf-8');
    const template = handlebars.compile(source);
    return template(templateData);
  }

  async sendVerificationEmail(
    email: string,
    otp: string,
    username?: string,
  ): Promise<Models.MessageSendingResponse> {
    const htmlContent = this.loadTemplate('email-verification-otp.html', {
      verificationCode: otp,
      username: username || '',
    });

    return this.sendEmail({
      to: email,
      subject: 'Verify Your Email - xmobit',
      htmlBody: htmlContent,
      tag: 'email-verification',
      trackOpens: true,
    });
  }

  async sendPasswordResetEmail(
    email: string,
    resetToken: string,
    username?: string,
  ): Promise<Models.MessageSendingResponse> {
    const baseURL =
      this.configService.get('BASE_URL') || 'http://localhost:3001';
    const resetLink = `${baseURL}/reset-password?token=${resetToken}`;

    const htmlContent = this.loadTemplate('password-reset.html', {
      username: username || '',
      resetLink: resetLink,
    });

    return this.sendEmail({
      to: email,
      subject: 'Password Reset - xmobit',
      htmlBody: htmlContent,
      tag: 'password-reset',
      trackOpens: true,
    });
  }

  async sendWelcomeEmail(
    email: string,
    username: string,
  ): Promise<Models.MessageSendingResponse> {
    const htmlContent = this.loadTemplate('welcome-email.html', {
      username: username,
      frontendUrl:
        this.configService.get('BASE_URL') || 'http://localhost:3001',
    });

    return this.sendEmail({
      to: email,
      subject: 'Welcome to xmobit!',
      htmlBody: htmlContent,
      tag: 'welcome',
      trackOpens: true,
    });
  }

  async send2FACode(
    email: string,
    code: string,
  ): Promise<Models.MessageSendingResponse> {
    const htmlContent = this.loadTemplate('2fa-code.html', {
      code: code,
    });

    return this.sendEmail({
      to: email,
      subject: '2FA Verification Code - xmobit',
      htmlBody: htmlContent,
      tag: '2fa-code',
      trackOpens: true,
    });
  }

  async sendLoginNotification(
    email: string,
    username: string,
    loginDetails: {
      ip?: string;
      userAgent?: string;
      location?: string;
      time?: Date;
    },
  ): Promise<Models.MessageSendingResponse> {
    const htmlContent = this.loadTemplate('login-notification.html', {
      username: username,
      loginTime:
        loginDetails.time?.toLocaleString() || new Date().toLocaleString(),
      ipAddress: loginDetails.ip || 'Unknown',
      location: loginDetails.location || 'Unknown',
      userAgent: loginDetails.userAgent || 'Unknown',
      frontendUrl:
        this.configService.get('BASE_URL') || 'http://localhost:3001',
    });

    return this.sendEmail({
      to: email,
      subject: 'New Login Detected - xmobit',
      htmlBody: htmlContent,
      tag: 'login-notification',
      trackOpens: true,
    });
  }
}
