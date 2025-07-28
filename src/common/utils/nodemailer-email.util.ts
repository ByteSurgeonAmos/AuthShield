import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
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
  attachments?: Array<{
    filename: string;
    content: string | Buffer;
    contentType?: string;
  }>;
}

export interface EmailSendResponse {
  messageId: string;
  accepted: string[];
  rejected: string[];
  response: string;
}

@Injectable()
export class NodemailerEmailService {
  private transporter: nodemailer.Transporter;
  private defaultFrom: string;

  constructor(private configService: ConfigService) {
    const host =
      this.configService.get<string>('EMAIL_HOST') || 'email-smtp.us-east-1.amazonaws.com';
    const port = parseInt(
      this.configService.get<string>('EMAIL_PORT') || '587',
    );
    const secure =
      this.configService.get<string>('EMAIL_SECURE') === 'true' || port === 465;
    const user =
      this.configService.get<string>('EMAIL_USER');
    const pass =
      this.configService.get<string>('EMAIL_PASS');

    this.transporter = nodemailer.createTransport({
      host,
      port,
      secure,
      auth: {
        user,
        pass,
      },
    });

    this.defaultFrom =
      this.configService.get<string>('NOTIFICATIONS_EMAIL') ||
      'no.reply@xmobit.com';

    this.transporter.verify((error, success) => {
      if (error) {
        console.error('❌ SMTP configuration error:', error);
      } else {
        console.log('✅ SMTP transporter ready for SES');
      }
    });
  }

  async sendEmail(options: EmailOptions): Promise<EmailSendResponse> {
    try {
      const mailOptions = {
        from: options.from || this.defaultFrom,
        to: Array.isArray(options.to) ? options.to.join(',') : options.to,
        subject: options.subject,
        html: options.htmlBody,
        text: options.textBody,
        replyTo: options.replyTo,
        cc: Array.isArray(options.cc) ? options.cc.join(',') : options.cc,
        bcc: Array.isArray(options.bcc) ? options.bcc.join(',') : options.bcc,
        attachments: options.attachments,
      };

      const result = await this.transporter.sendMail(mailOptions);

      Logger.log('✅ Email sent successfully via AWS SES:', {
        messageId: result.messageId
      }, 'NodemailerEmailService');

      return {
        messageId: result.messageId,
        accepted: result.accepted,
        rejected: result.rejected,
        response: result.response,
      };
    } catch (error) {
      Logger.error('❌ Failed to send email via AWS SES:', {
        error: error.message,
        code: error.code
      }, 'NodemailerEmailService');
      if (error.code === 'MessageRejected') {
        throw new Error('Email rejected: Verify sender/recipient or check SES sandbox mode');
      }
      throw new Error(`Failed to send email: ${error.message}`);
    }
  }


  async sendBulkEmails(emails: EmailOptions[]): Promise<EmailSendResponse[]> {
    try {
      const results = await Promise.all(
        emails.map((email) => this.sendEmail(email)),
      );

      return results;
    } catch (error) {
      console.error('❌ Failed to send bulk emails via Nodemailer:', error);
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

    try {
      const source = fs.readFileSync(templatePath, 'utf-8');
      const template = handlebars.compile(source);
      return template(templateData);
    } catch (error) {
      console.warn(`⚠️ Template ${templateName} not found, using simple HTML`);
      // Fallback to simple HTML if template doesn't exist
      return this.generateSimpleTemplate(templateData);
    }
  }

  private generateSimpleTemplate(data: any): string {
    const { title, message, code, username, resetLink } = data;

    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${title || 'XMobit Notification'}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        .logo {
            text-align: center;
            margin-bottom: 20px;
        }
        .logo img {
            max-width: 150px;
        }
        .content {
            text-align: center;
        }
        .content h2 {
            color: #333333;
            margin-bottom: 20px;
        }
        .message {
            font-size: 16px;
            color: #666666;
            margin: 20px 0;
            line-height: 1.5;
        }
        .code {
            display: inline-block;
            font-size: 24px;
            color: #333333;
            background-color: #f9f9f9;
            padding: 15px 25px;
            border-radius: 5px;
            margin: 20px 0;
            letter-spacing: 3px;
            font-weight: bold;
        }
        .button {
            display: inline-block;
            background-color: #007bff;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 5px;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            margin-top: 30px;
            color: #aaaaaa;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <img src="https://firebasestorage.googleapis.com/v0/b/derrivepro.appspot.com/o/Logo%20Variation%202.png?alt=media&token=910ebcff-93b9-450a-8835-471f10c80750" alt="XMobit Logo">
        </div>
        <div class="content">
            <h2>${title || 'XMobit Notification'}</h2>
            ${username ? `<p>Hello ${username},</p>` : ''}
            ${message ? `<p class="message">${message}</p>` : ''}
            ${code ? `<div class="code">${code}</div>` : ''}
            ${resetLink ? `<a href="${resetLink}" class="button">Reset Password</a>` : ''}
        </div>
        <div class="footer">
            <p>&copy; 2024 XMobit. All rights reserved.</p>
        </div>
    </div>
</body>
</html>`;
  }

  async sendVerificationEmail(
    email: string,
    otp: string,
    username?: string,
  ): Promise<EmailSendResponse> {
    const htmlContent = this.loadTemplate('email-verification-otp.html', {
      verificationCode: otp,
      username: username || '',
      title: 'Verify Your Email - XMobit',
      message:
        'Please use the following verification code to verify your email address:',
      code: otp,
    });

    return this.sendEmail({
      to: email,
      subject: 'Verify Your Email - XMobit',
      htmlBody: htmlContent,
    });
  }

  async sendPasswordResetEmail(
    email: string,
    resetToken: string,
    username?: string,
  ): Promise<EmailSendResponse> {
    const baseURL =
      this.configService.get('BASE_URL') || 'http://localhost:3001';
    const resetLink = `${baseURL}/reset-password?token=${resetToken}`;

    const htmlContent = this.loadTemplate('password-reset.html', {
      username: username || '',
      resetLink: resetLink,
      title: 'Password Reset - XMobit',
      message: 'Click the button below to reset your password:',
    });

    return this.sendEmail({
      to: email,
      subject: 'Password Reset - XMobit',
      htmlBody: htmlContent,
    });
  }

  async sendWelcomeEmail(
    email: string,
    username: string,
  ): Promise<EmailSendResponse> {
    const htmlContent = this.loadTemplate('welcome-email.html', {
      username: username,
      frontendUrl:
        this.configService.get('BASE_URL') || 'http://localhost:3001',
      title: 'Welcome to XMobit!',
      message: `Welcome to XMobit, ${username}! Your account has been successfully created and verified.`,
    });

    return this.sendEmail({
      to: email,
      subject: 'Welcome to XMobit!',
      htmlBody: htmlContent,
    });
  }

  async send2FACode(email: string, code: string): Promise<EmailSendResponse> {
    const htmlContent = this.loadTemplate('2fa-code.html', {
      code: code,
      title: '2FA Verification Code - XMobit',
      message: 'Your two-factor authentication code is:',
    });

    return this.sendEmail({
      to: email,
      subject: '2FA Verification Code - XMobit',
      htmlBody: htmlContent,
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
  ): Promise<EmailSendResponse> {
    const htmlContent = this.loadTemplate('login-notification.html', {
      username: username,
      loginTime:
        loginDetails.time?.toLocaleString() || new Date().toLocaleString(),
      ipAddress: loginDetails.ip || 'Unknown',
      location: loginDetails.location || 'Unknown',
      userAgent: loginDetails.userAgent || 'Unknown',
      frontendUrl:
        this.configService.get('BASE_URL') || 'http://localhost:3001',
      title: 'New Login Detected - XMobit',
      message: `A new login was detected on your XMobit account.`,
    });

    return this.sendEmail({
      to: email,
      subject: 'New Login Detected - XMobit',
      htmlBody: htmlContent,
    });
  }

  async verifyConnection(): Promise<boolean> {
    try {
      await this.transporter.verify();
      console.log('✅ Email service connection verified');
      return true;
    } catch (error) {
      console.error('❌ Email service connection failed:', error);
      return false;
    }
  }
}
