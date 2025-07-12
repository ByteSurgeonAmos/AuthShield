import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthNotification } from '../entities/auth-notification.entity';
import { PostmarkEmailService } from '../../common/utils/postmark-email.util';

@Injectable()
export class NotificationService {
  constructor(
    @InjectRepository(AuthNotification)
    private notificationRepository: Repository<AuthNotification>,
    private config: ConfigService,
    private postmarkEmailService: PostmarkEmailService,
  ) {}
  async sendLoginAttemptNotification(
    email: string,
    username: string,
  ): Promise<void> {
    try {
      const emailContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background-color: #f8f9fa; padding: 30px; border-radius: 8px;">
            <h2 style="color: #dc3545; margin-bottom: 20px;">⚠️ Failed Login Attempt Detected</h2>
            <p style="color: #666; margin-bottom: 20px;">Hello ${username},</p>
            <p style="color: #666; margin-bottom: 30px;">
              We detected a failed login attempt on your account. Here are the details:
            </p>
            <div style="background-color: #fff; padding: 20px; border-radius: 4px; margin-bottom: 30px;">
              <p style="margin: 10px 0; color: #333;"><strong>Time:</strong> ${new Date().toLocaleString()}</p>
              <p style="margin: 10px 0; color: #333;"><strong>Email:</strong> ${email}</p>
            </div>
            <p style="color: #666; margin-bottom: 30px;">
              If this wasn't you, please change your password immediately and contact support.
            </p>
            <p style="color: #666; margin-bottom: 30px;">
              If this was you, please ensure you're using the correct credentials.
            </p>
            <p style="color: #666; margin-top: 20px; font-size: 14px;">
              Best regards,<br>
              The xmobit Team
            </p>
          </div>
        </div>
      `;

      await this.postmarkEmailService.sendEmail({
        to: email,
        subject: 'Failed Login Attempt - xmobit',
        htmlBody: emailContent,
        tag: 'failed-login-attempt',
        trackOpens: true,
      });
    } catch (error) {
      console.error('Failed to send login attempt notification:', error);
    }
  }

  async sendAccountVerificationToEmail(
    email: string,
    otpCode: string,
  ): Promise<void> {
    try {
      await this.postmarkEmailService.sendVerificationEmail(email, otpCode);
    } catch (error) {
      console.error('Failed to send account verification email:', error);
    }
  }

  async sendOTPToEmail(email: string, otpCode: string): Promise<void> {
    try {
      const emailContent = `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background-color: #f8f9fa; padding: 30px; border-radius: 8px; text-align: center;">
            <h2 style="color: #333; margin-bottom: 20px;">Your Login Verification Code</h2>
            <p style="color: #666; margin-bottom: 30px;">
              Use the code below to complete your login process:
            </p>
            <div style="background-color: #007bff; color: white; padding: 15px 30px; border-radius: 4px; font-size: 24px; font-weight: bold; letter-spacing: 3px; display: inline-block;">
              ${otpCode}
            </div>
            <p style="color: #666; margin-top: 30px; font-size: 14px;">
              This code will expire in 30 minutes. Enter this code to complete your login.
            </p>
            <p style="color: #666; margin-top: 20px; font-size: 14px;">
              Best regards,<br>
              The xmobit Team
            </p>
          </div>
        </div>
      `;

      await this.postmarkEmailService.sendEmail({
        to: email,
        subject: 'Login Verification Code - xmobit',
        htmlBody: emailContent,
        tag: 'login-verification',
        trackOpens: true,
      });
    } catch (error) {
      console.error('Failed to send OTP email:', error);
    }
  }

  async createAuthNotification(
    userId: string,
    email: string,
    title: string,
    message: string,
    type: string,
    priority: string,
  ): Promise<AuthNotification> {
    try {
      const notification = this.notificationRepository.create({
        userId,
        email,
        title,
        message,
        type,
        priority,
        isRead: false,
      });

      return await this.notificationRepository.save(notification);
    } catch (error) {
      console.error('Failed to create auth notification:', error);
      throw error;
    }
  }

  async getUserNotifications(
    userId: string,
    limit: number = 20,
  ): Promise<AuthNotification[]> {
    return await this.notificationRepository.find({
      where: { userId },
      order: { createdAt: 'DESC' },
      take: limit,
    });
  }

  async markNotificationAsRead(notificationId: string): Promise<void> {
    await this.notificationRepository.update(notificationId, {
      isRead: true,
      readAt: new Date(),
    });
  }
  async getUnreadNotifications(userId: string): Promise<AuthNotification[]> {
    return await this.notificationRepository.find({
      where: { userId, isRead: false },
      order: { createdAt: 'DESC' },
    });
  }

  async getAllNotifications(limit: number = 50): Promise<AuthNotification[]> {
    return await this.notificationRepository.find({
      order: { createdAt: 'DESC' },
      take: limit,
      relations: ['user'],
    });
  }

  async deleteNotification(notificationId: string): Promise<void> {
    await this.notificationRepository.delete(notificationId);
  }
}
