import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';
import { AuthNotification } from '../entities/auth-notification.entity';
import * as nodemailer from 'nodemailer';

@Injectable()
export class NotificationService {
  constructor(
    @InjectRepository(AuthNotification)
    private notificationRepository: Repository<AuthNotification>,
    private config: ConfigService,
  ) {}
  private async getTransporter() {
    return nodemailer.createTransport({
      host: 'mail.privateemail.com',
      secure: true,
      port: 465,
      auth: {
        user: this.config.get<string>('NOTIFICATIONS_EMAIL'),
        pass: this.config.get<string>('EMAIL_PASS'),
      },
    });
  }

  async sendLoginAttemptNotification(
    email: string,
    username: string,
  ): Promise<void> {
    try {
      const transporter = await this.getTransporter();

      const emailContent = `
        <h2>Failed Login Attempt Detected</h2>
        <p>Hello ${username},</p>
        <p>We detected a failed login attempt on your account.</p>
        <ul>
          <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
          <li><strong>Email:</strong> ${email}</li>
        </ul>
        <p>If this wasn't you, please change your password immediately and contact support.</p>
        <p>If this was you, please ensure you're using the correct credentials.</p>
      `;

      await transporter.sendMail({
        from: this.config.get<string>('NOTIFICATIONS_EMAIL'),
        to: email,
        subject: 'Failed Login Attempt - xmobit',
        html: emailContent,
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
      const transporter = await this.getTransporter();

      const emailContent = `
        <h2>Account Verification Required</h2>
        <p>Your verification code is: <strong>${otpCode}</strong></p>
        <p>This code will expire in 30 minutes.</p>
        <p>Please use this code to verify your account.</p>
      `;

      await transporter.sendMail({
        from: this.config.get<string>('NOTIFICATIONS_EMAIL'),
        to: email,
        subject: 'Account Verification - xmobit',
        html: emailContent,
      });
    } catch (error) {
      console.error('Failed to send account verification email:', error);
    }
  }

  async sendOTPToEmail(email: string, otpCode: string): Promise<void> {
    try {
      const transporter = await this.getTransporter();

      const emailContent = `
        <h2>Your Login Verification Code</h2>
        <p>Your verification code is: <strong>${otpCode}</strong></p>
        <p>This code will expire in 30 minutes.</p>
        <p>Enter this code to complete your login.</p>
      `;

      await transporter.sendMail({
        from: this.config.get<string>('NOTIFICATIONS_EMAIL'),
        to: email,
        subject: 'Login Verification Code - xmobit',
        html: emailContent,
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
