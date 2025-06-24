import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Repository } from 'typeorm';
import { User } from './entities/auth.entity';
import { UserRole, UserRoleType } from './entities/user-role.entity';
import { UserDetails } from './entities/user-details.entity';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import * as nodemailer from 'nodemailer';
import { randomBytes } from 'crypto';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs';
import * as path from 'path';
import * as handlebars from 'handlebars';
import { generateOtp } from 'src/common/generate-otp';
import { SmsService } from 'src/sms/sms.service';
import { v4 as uuidv4 } from 'uuid';
import * as speakeasy from 'speakeasy';
import * as qrcode from 'qrcode';
import { TwoFactorMethod } from './dto/setup-2fa.dto';
import { SecurityAuditService } from './services/security-audit.service';
import { NotificationService } from './services/notification.service';
import {
  generateRandomUsername,
  generateRandomProfileImage,
  ensureUniqueUsername,
} from 'src/common/username-generator';
import * as crypto from 'crypto';
import { SecurityQuestion } from './entities/security-question.entity';
import {
  SetSecurityQuestionDto,
  VerifySecurityQuestionDto,
  UpdateSecurityQuestionDto,
} from './dto/security-question.dto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    @InjectRepository(UserRole) private roleRepository: Repository<UserRole>,
    @InjectRepository(UserDetails)
    private detailsRepository: Repository<UserDetails>,
    @InjectRepository(SecurityQuestion)
    private securityQuestionRepository: Repository<SecurityQuestion>,
    private jwtService: JwtService,
    private config: ConfigService,
    private smsService: SmsService,
    private securityAuditService: SecurityAuditService,
    private notificationService: NotificationService,
  ) {}

  async findAll(): Promise<User[]> {
    const users = await this.userRepository.find({
      relations: ['roles', 'details'],
    });
    return users;
  }

  async findOne(userId: string): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { userId },
      relations: ['roles', 'details'],
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  async findByEmail(email: string): Promise<User> {
    const user = await this.userRepository.findOne({
      where: { email },
      relations: ['roles', 'details'],
    });
    return user;
  }
  async update(userId: string, updateUserDto: UpdateUserDto) {
    const user = await this.findOne(userId);

    // Check username change restrictions (similar to security questions)
    if (updateUserDto.username && updateUserDto.username !== user.username) {
      if (user.usernameChanged) {
        throw new BadRequestException('Username can only be changed once');
      }

      // Check if new username is unique
      const existingUser = await this.userRepository.findOne({
        where: { username: updateUserDto.username },
      });

      if (existingUser) {
        throw new BadRequestException('Username already exists');
      }

      // Mark username as changed
      user.usernameChanged = true;

      // Record security event for username change
      await this.securityAuditService.recordSecurityEvent({
        eventType: 'USERNAME_CHANGED',
        userId: userId,
        email: user.email,
        additionalData: {
          oldUsername: user.username,
          newUsername: updateUserDto.username,
        },
      });
    }

    // Update user basic info
    Object.assign(user, updateUserDto);

    // If updating user details
    if (
      updateUserDto.fullname ||
      updateUserDto.country ||
      updateUserDto.userBio
    ) {
      if (!user.details) {
        // Create new details if they don't exist
        const details = this.detailsRepository.create({
          userId: user.userId,
          fullname: updateUserDto.fullname,
          country: updateUserDto.country,
          userBio: updateUserDto.userBio,
        });
        await this.detailsRepository.save(details);
      } else {
        // Update existing details
        if (updateUserDto.fullname)
          user.details.fullname = updateUserDto.fullname;
        if (updateUserDto.country) user.details.country = updateUserDto.country;
        if (updateUserDto.userBio) user.details.userBio = updateUserDto.userBio;
        await this.detailsRepository.save(user.details);
      }
    }

    return await this.userRepository.save(user);
  }

  async remove(userId: string): Promise<void> {
    const user = await this.findOne(userId);

    // Delete related records first
    await this.roleRepository.delete({ userId });
    await this.detailsRepository.delete({ userId });

    // Delete user
    const result = await this.userRepository.delete({ userId });
    if (result.affected === 0) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }
  }

  async sendVerificationEmail(email: string, token: string) {
    const transporter = nodemailer.createTransporter({
      host: 'mail.privateemail.com',
      secure: true,
      port: 465,
      auth: {
        user: this.config.get<string>('NOTIFICATIONS_EMAIL'),
        pass: this.config.get<string>('EMAIL_PASS'),
      },
    });

    const verificationLink = `${this.config.get<string>('BASE_URL')}/api/v1/users/verify?token=${token}`;

    try {
      const templatePath = path.join(
        __dirname,
        '..',
        'templates',
        'verification-email.html',
      );
      const source = fs.readFileSync(templatePath, 'utf-8').toString();
      const template = handlebars.compile(source);
      const htmlContent = template({ verificationLink });

      await transporter.sendMail({
        from: this.config.get<string>('NOTIFICATIONS_EMAIL'),
        to: email,
        subject: 'Verify Your Email - xmobit',
        html: htmlContent,
        attachments: [
          {
            filename: 'logo.svg',
            path: path.join(__dirname, '..', 'assets', 'logo.svg'),
            cid: 'logo',
          },
        ],
      });
    } catch (error) {
      console.error('Failed to send verification email:', error);
      await transporter.sendMail({
        from: this.config.get<string>('NOTIFICATIONS_EMAIL'),
        to: email,
        subject: 'Verify Your Email - xmobit',
        text: `Please verify your email by clicking this link: ${verificationLink}`,
      });
    }
  }
  async create(createUserDto: CreateUserDto) {
    const existingUser = await this.userRepository.findOne({
      where: [
        { email: createUserDto.email },
        { username: createUserDto.username },
      ],
    });

    if (existingUser) {
      if (existingUser.email === createUserDto.email) {
        throw new BadRequestException('Email already exists');
      }
      if (existingUser.username === createUserDto.username) {
        throw new BadRequestException('Username already exists');
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(createUserDto.password, 12);

    // Generate verification tokens
    const emailVerificationToken = randomBytes(32).toString('hex');
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 24);

    // Generate unique user ID
    const userId = uuidv4();

    // Generate random username if not provided (for crypto trading platform)
    let finalUsername = createUserDto.username;
    if (!finalUsername) {
      finalUsername = await ensureUniqueUsername(this.userRepository);
    }

    // Generate random profile image
    const profileImageUrl = generateRandomProfileImage(finalUsername);

    // Get next ID from sequence (you might need to implement this differently)
    const lastUser = await this.userRepository
      .createQueryBuilder('user')
      .orderBy('user.id', 'DESC')
      .getOne();
    const nextId = (lastUser?.id || 0) + 1;

    // Create user
    const user = this.userRepository.create({
      userId,
      id: nextId,
      username: finalUsername,
      email: createUserDto.email,
      password: hashedPassword,
      phoneNumber: createUserDto.phoneNumber,
      emailVerificationToken,
      emailVerificationExpires: tokenExpiry,
      dateRegistrated: new Date().toISOString(),
      authProvider: 'local',
      countryCode: createUserDto.countryCode,
    });

    const savedUser = await this.userRepository.save(user);

    // Create default role
    const userRole = this.roleRepository.create({
      userId: savedUser.userId,
      roles: UserRoleType.USER,
    });
    await this.roleRepository.save(userRole);

    // Create user details if provided
    if (createUserDto.fullname || createUserDto.country) {
      const userDetails = this.detailsRepository.create({
        userId: savedUser.userId,
        fullname: createUserDto.fullname,
        country: createUserDto.country,
      });
      await this.detailsRepository.save(userDetails);
    }

    // Send verification email
    await this.sendVerificationEmail(
      savedUser.email,
      savedUser.emailVerificationToken,
    );
    return {
      userId: savedUser.userId,
      username: savedUser.username,
      email: savedUser.email,
      profileImage: profileImageUrl,
      message:
        'User created successfully. Please check your email for verification.',
    };
  }

  async resendVerificationToken(email: string): Promise<{ message: string }> {
    const user = await this.findByEmail(email);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.emailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    const newVerificationToken = randomBytes(32).toString('hex');
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 24);

    user.emailVerificationToken = newVerificationToken;
    user.emailVerificationExpires = tokenExpiry;

    await this.userRepository.save(user);
    await this.sendVerificationEmail(user.email, user.emailVerificationToken);

    return { message: 'Verification token resent successfully' };
  }

  async verifyEmail(token: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({
      where: { emailVerificationToken: token },
    });

    if (!user) {
      throw new NotFoundException('Invalid or expired verification token');
    }

    const currentTime = new Date();
    if (currentTime > user.emailVerificationExpires) {
      throw new BadRequestException(
        'Verification token has expired. Please request a new token.',
      );
    }

    if (user.emailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    user.emailVerified = true;
    user.isVerified = true;
    user.emailVerificationToken = null;
    user.emailVerificationExpires = null;

    await this.userRepository.save(user);

    return { message: 'Email verified successfully' };
  }

  async sendOTP(phoneNumber: string, userId: string): Promise<void> {
    try {
      const user = await this.findOne(userId);

      const otp = generateOtp(6, {
        digitsOnly: true,
        includeSpecialChars: false,
      });

      user.otpCode = otp;
      user.phoneNumber = phoneNumber;
      user.otpExpiry = new Date(
        new Date().getTime() + 60 * 60 * 1000,
      ).toISOString();

      await this.smsService.sendSms(
        phoneNumber,
        `Your verification code is: ${otp}. This code will expire in 60 minutes. Do not share this code with anyone.`,
      );

      await this.userRepository.save(user);
    } catch (error) {
      console.error('Error sending OTP:', error);
      throw new BadRequestException('Failed to send OTP');
    }
  }

  async verifyOTP(otp: string, userId: string): Promise<{ message: string }> {
    try {
      const user = await this.findOne(userId);

      if (!user.otpExpiry) {
        throw new BadRequestException('No OTP found for this user');
      }

      const currentTime = new Date();
      const otpExpiryTime = new Date(user.otpExpiry);

      if (currentTime > otpExpiryTime) {
        throw new BadRequestException('OTP has expired');
      }

      if (!user.otpCode || user.otpCode !== otp) {
        throw new BadRequestException('Invalid OTP');
      }

      user.phoneNoVerified = true;
      user.otpCode = null;
      user.otpExpiry = null;

      await this.userRepository.save(user);
      return { message: 'Phone verification successful' };
    } catch (error) {
      console.error('Error verifying OTP:', error);
      throw error;
    }
  }

  async assignRole(
    userId: string,
    role: UserRoleType,
  ): Promise<{ message: string }> {
    const user = await this.findOne(userId);

    // Check if role already exists
    const existingRole = await this.roleRepository.findOne({
      where: { userId, roles: role },
    });

    if (existingRole) {
      throw new BadRequestException('User already has this role');
    }

    const userRole = this.roleRepository.create({
      userId,
      roles: role,
    });

    await this.roleRepository.save(userRole);
    return { message: `Role ${role} assigned successfully` };
  }

  async removeRole(
    userId: string,
    role: UserRoleType,
  ): Promise<{ message: string }> {
    const result = await this.roleRepository.delete({ userId, roles: role });

    if (result.affected === 0) {
      throw new NotFoundException('Role not found for this user');
    }

    return { message: `Role ${role} removed successfully` };
  }
  async setupTwoFactorAuthentication(
    userId: string,
    method: TwoFactorMethod,
  ): Promise<{ message: string; secret?: string; qrCodeUrl?: string }> {
    const user = await this.findOne(userId);

    let secret;
    let qrCodeUrl;

    if (method === TwoFactorMethod.AUTHENTICATOR) {
      // Generate secret for authenticator app
      secret = speakeasy.generateSecret({
        name: `xmobit (${user.email})`,
        length: 20,
      });

      // Generate QR code URL for the secret
      qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
    } else {
      throw new BadRequestException('Invalid 2FA method');
    }

    // Save the secret to the user record
    user.twoFactorSecret = secret.base32;
    user.is2FaEnabled = true;

    await this.userRepository.save(user);

    return {
      message: 'Two-factor authentication setup successfully',
      secret: secret.base32,
      qrCodeUrl,
    };
  }

  async verifyTwoFactorAuthentication(
    userId: string,
    token: string,
  ): Promise<{ message: string }> {
    const user = await this.findOne(userId);

    if (!user.twoFactorSecret) {
      throw new BadRequestException('Two-factor authentication is not enabled');
    }

    // Verify the token
    const isValid = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token,
    });

    if (!isValid) {
      throw new BadRequestException('Invalid two-factor authentication token');
    }

    return { message: 'Two-factor authentication verified successfully' };
  }

  async disableTwoFactorAuthentication(
    userId: string,
  ): Promise<{ message: string }> {
    const user = await this.findOne(userId);

    user.is2FaEnabled = false;
    user.twoFactorSecret = null;

    await this.userRepository.save(user);

    return { message: 'Two-factor authentication disabled successfully' };
  }

  // Login notification email
  async sendLoginNotification(user: User, loginDetails: any) {
    if (!user.loginNotificationEmail) {
      return; // User has disabled login notifications
    }

    const transporter = nodemailer.createTransporter({
      host: 'mail.privateemail.com',
      secure: true,
      port: 465,
      auth: {
        user: this.config.get<string>('NOTIFICATIONS_EMAIL'),
        pass: this.config.get<string>('EMAIL_PASS'),
      },
    });

    const emailContent = `
      <h2>New Login Detected</h2>
      <p>Hello ${user.username},</p>
      <p>We detected a new login to your account:</p>
      <ul>
        <li><strong>Time:</strong> ${new Date().toLocaleString()}</li>
        <li><strong>IP Address:</strong> ${loginDetails.ip || 'Unknown'}</li>
        <li><strong>Device:</strong> ${loginDetails.userAgent || 'Unknown'}</li>
      </ul>
      <p>If this wasn't you, please change your password immediately and contact support.</p>
    `;

    try {
      await transporter.sendMail({
        from: this.config.get<string>('NOTIFICATIONS_EMAIL'),
        to: user.email,
        subject: 'New Login Detected - xmobit',
        html: emailContent,
      });
    } catch (error) {
      console.error('Failed to send login notification:', error);
    }
  }

  // 2FA Setup
  async setup2FA(userId: string, method: TwoFactorMethod): Promise<any> {
    const user = await this.findOne(userId);

    if (method === TwoFactorMethod.AUTHENTICATOR) {
      const secret = speakeasy.generateSecret({
        name: `Xmobit (${user.email})`,
        issuer: 'Xmobit',
        length: 32,
      });

      // Generate QR code
      const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);

      // Store the secret temporarily (user needs to verify before enabling)
      user.twoFactorSecret = secret.base32;
      user.twoFactorMethod = method;
      await this.userRepository.save(user);

      return {
        secret: secret.base32,
        qrCode: qrCodeUrl,
        message:
          'Scan the QR code with your authenticator app and enter the code to verify',
      };
    } else {
      user.twoFactorMethod = method;
      await this.userRepository.save(user);

      return {
        message: `2FA method set to ${method}. You can now use this for login verification.`,
      };
    }
  }

  async verify2FASetup(
    userId: string,
    token: string,
  ): Promise<{ message: string }> {
    const user = await this.findOne(userId);

    if (!user.twoFactorSecret || !user.twoFactorMethod) {
      throw new BadRequestException('No 2FA setup in progress');
    }

    if (user.twoFactorMethod === TwoFactorMethod.AUTHENTICATOR) {
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token,
        window: 2,
      });

      if (!verified) {
        throw new BadRequestException('Invalid authenticator code');
      }
    }

    // Enable 2FA
    user.is2FaEnabled = true;
    await this.userRepository.save(user);

    return { message: '2FA enabled successfully' };
  }

  // Send 2FA code (for email/phone methods)
  async send2FACode(userId: string): Promise<{ message: string }> {
    const user = await this.findOne(userId);

    if (!user.is2FaEnabled || !user.twoFactorMethod) {
      throw new BadRequestException('2FA is not enabled for this user');
    }

    const code = generateOtp(6, { digitsOnly: true });
    const expiryTime = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Store the code temporarily
    user.otpCode = code;
    user.otpExpiry = expiryTime.toISOString();
    await this.userRepository.save(user);

    if (user.twoFactorMethod === TwoFactorMethod.EMAIL) {
      await this.send2FAEmail(user.email, code);
    } else if (
      user.twoFactorMethod === TwoFactorMethod.PHONE &&
      user.phoneNumber
    ) {
      await this.smsService.sendSms(
        user.phoneNumber,
        `Your 2FA verification code is: ${code}. This code will expire in 10 minutes.`,
      );
    }

    return { message: `2FA code sent to your ${user.twoFactorMethod}` };
  }

  // Send 2FA email
  private async send2FAEmail(email: string, code: string) {
    const transporter = nodemailer.createTransporter({
      host: 'smtp.privateemail.com',
      secure: true,
      port: 465,
      auth: {
        user: this.config.get<string>('NOTIFICATIONS_EMAIL'),
        pass: this.config.get<string>('EMAIL_PASS'),
      },
    });

    await transporter.sendMail({
      from: this.config.get<string>('NOTIFICATIONS_EMAIL'),
      to: email,
      subject: 'Your 2FA Verification Code',
      html: `
        <h2>2FA Verification Code</h2>
        <p>Your verification code is: <strong>${code}</strong></p>
        <p>This code will expire in 10 minutes.</p>
      `,
    });
  }

  // Verify 2FA code during login
  async verify2FACode(userId: string, token: string): Promise<boolean> {
    const user = await this.findOne(userId);

    if (!user.is2FaEnabled) {
      throw new BadRequestException('2FA is not enabled for this user');
    }

    if (user.twoFactorMethod === TwoFactorMethod.AUTHENTICATOR) {
      return speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token,
        window: 2,
      });
    } else {
      // For email/phone 2FA
      if (!user.otpCode || !user.otpExpiry) {
        throw new BadRequestException(
          'No 2FA code found. Please request a new one.',
        );
      }

      const currentTime = new Date();
      const expiryTime = new Date(user.otpExpiry);

      if (currentTime > expiryTime) {
        throw new BadRequestException('2FA code has expired');
      }

      const isValid = user.otpCode === token;

      if (isValid) {
        // Clear the used code
        user.otpCode = null;
        user.otpExpiry = null;
        await this.userRepository.save(user);
      }

      return isValid;
    }
  }

  // Disable 2FA
  async disable2FA(
    userId: string,
    currentPassword: string,
  ): Promise<{ message: string }> {
    const user = await this.findOne(userId);

    // Verify current password
    const isPasswordValid = await bcrypt.compare(
      currentPassword,
      user.password,
    );
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid password');
    }

    user.is2FaEnabled = false;
    user.twoFactorSecret = null;
    user.twoFactorMethod = null;
    user.otpCode = null;
    user.otpExpiry = null;

    await this.userRepository.save(user);

    return { message: '2FA disabled successfully' };
  }

  // Analytics methods
  async getUserAnalytics(timeframe: string = 'monthly') {
    const endDate = new Date();
    let startDate = new Date();

    switch (timeframe) {
      case 'daily':
        startDate.setDate(endDate.getDate() - 1);
        break;
      case 'weekly':
        startDate.setDate(endDate.getDate() - 7);
        break;
      case 'monthly':
        startDate.setMonth(endDate.getMonth() - 1);
        break;
      case 'yearly':
        startDate.setFullYear(endDate.getFullYear() - 1);
        break;
    }

    const totalUsers = await this.userRepository.count();
    const activeUsers = await this.userRepository.count({
      where: { isAccountActive: true },
    });
    const verifiedUsers = await this.userRepository.count({
      where: { emailVerified: true },
    });
    const twoFAEnabledUsers = await this.userRepository.count({
      where: { is2FaEnabled: true },
    });

    // Recent registrations
    const recentRegistrations = await this.userRepository
      .createQueryBuilder('user')
      .where('user.dateRegistrated >= :startDate', {
        startDate: startDate.toISOString(),
      })
      .getCount();

    // Users by auth provider
    const authProviders = await this.userRepository
      .createQueryBuilder('user')
      .select('user.authProvider, COUNT(*) as count')
      .groupBy('user.authProvider')
      .getRawMany();

    // Users by country (from details)
    const usersByCountry = await this.detailsRepository
      .createQueryBuilder('details')
      .select('details.country, COUNT(*) as count')
      .where('details.country IS NOT NULL')
      .groupBy('details.country')
      .limit(10)
      .getRawMany();

    return {
      summary: {
        totalUsers,
        activeUsers,
        verifiedUsers,
        twoFAEnabledUsers,
        recentRegistrations,
      },
      authProviders,
      usersByCountry,
      timeframe,
      periodStart: startDate,
      periodEnd: endDate,
    };
  }

  async getLoginAnalytics(timeframe: string = 'monthly') {
    const endDate = new Date();
    let startDate = new Date();

    switch (timeframe) {
      case 'daily':
        startDate.setDate(endDate.getDate() - 1);
        break;
      case 'weekly':
        startDate.setDate(endDate.getDate() - 7);
        break;
      case 'monthly':
        startDate.setMonth(endDate.getMonth() - 1);
        break;
      case 'yearly':
        startDate.setFullYear(endDate.getFullYear() - 1);
        break;
    }

    // Recent logins
    const recentLogins = await this.userRepository
      .createQueryBuilder('user')
      .where('user.lastLogin >= :startDate', { startDate })
      .getCount();

    // Failed login attempts
    const failedAttempts = await this.userRepository
      .createQueryBuilder('user')
      .select('SUM(user.failedLoginAttempts)', 'totalFailedAttempts')
      .getRawOne();

    // Locked accounts
    const lockedAccounts = await this.userRepository.count({
      where: { accountLockedUntil: new Date() },
    });

    return {
      recentLogins,
      totalFailedAttempts: parseInt(failedAttempts.totalFailedAttempts) || 0,
      lockedAccounts,
      timeframe,
      periodStart: startDate,
      periodEnd: endDate,
    };
  }

  async getSecurityAnalytics() {
    // Users with 2FA enabled
    const twoFAStats = await this.userRepository
      .createQueryBuilder('user')
      .select('user.twoFactorMethod, COUNT(*) as count')
      .where('user.is2FaEnabled = :enabled', { enabled: true })
      .groupBy('user.twoFactorMethod')
      .getRawMany();

    // Password security metrics
    const unverifiedUsers = await this.userRepository.count({
      where: { emailVerified: false },
    });

    const inactiveUsers = await this.userRepository.count({
      where: { isAccountActive: false },
    });

    return {
      twoFAStats,
      unverifiedUsers,
      inactiveUsers,
      securityScore: this.calculateSecurityScore({
        twoFAEnabled: twoFAStats.length > 0,
        unverifiedCount: unverifiedUsers,
        inactiveCount: inactiveUsers,
      }),
    };
  }

  private calculateSecurityScore(metrics: any): number {
    let score = 100;

    if (metrics.unverifiedCount > 0) {
      score -= Math.min(metrics.unverifiedCount * 2, 30);
    }

    if (metrics.inactiveCount > 0) {
      score -= Math.min(metrics.inactiveCount * 1, 20);
    }

    if (!metrics.twoFAEnabled) {
      score -= 25;
    }

    return Math.max(score, 0);
  }
  // Enhanced login with 2FA support
  async enhancedLogin(
    loginDto: LoginUserDto,
    loginDetails: any,
  ): Promise<{
    requiresTwoFactor?: boolean;
    temporaryToken?: string;
    accesstoken?: string;
    user?: any;
    message?: string;
  }> {
    const user = await this.findByEmail(loginDto.email);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Check if account is active
    if (!user.isAccountActive) {
      throw new UnauthorizedException('Account is not active');
    }

    // Check if account is locked
    if (user.accountLockedUntil && new Date() < user.accountLockedUntil) {
      const remainingTime = Math.ceil(
        (user.accountLockedUntil.getTime() - new Date().getTime()) / 60000,
      );
      throw new UnauthorizedException(
        `Account is locked. Please try again in ${remainingTime} minutes.`,
      );
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(
      loginDto.password,
      user.password,
    );

    if (!isPasswordValid) {
      // Increment failed login attempts
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;

      // Lock account after 5 failed attempts
      if (user.failedLoginAttempts >= 5) {
        user.accountLockedUntil = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
      }

      await this.userRepository.save(user);

      // Record failed login attempt
      await this.securityAuditService.recordSecurityEvent({
        eventType: 'FAILED_LOGIN',
        reason: 'Invalid password',
        userId: user.userId,
        email: user.email,
        ipAddress: loginDetails.ip,
        userAgent: loginDetails.userAgent,
      });

      throw new UnauthorizedException('Invalid credentials');
    }

    // Check email verification
    if (!user.emailVerified) {
      throw new UnauthorizedException('Email is not verified');
    }

    // Check if 2FA is enabled
    if (user.is2FaEnabled) {
      // For email/phone 2FA, send code automatically
      if (
        user.twoFactorMethod === TwoFactorMethod.EMAIL ||
        (user.twoFactorMethod === TwoFactorMethod.PHONE && user.phoneNumber)
      ) {
        await this.send2FACode(user.userId);
      }

      // Generate temporary token for 2FA verification (valid for 10 minutes)
      const temporaryPayload = {
        userId: user.userId,
        email: user.email,
        purpose: '2FA_VERIFICATION',
        exp: Math.floor(Date.now() / 1000) + 10 * 60, // 10 minutes
      };

      const temporaryToken = this.jwtService.sign(temporaryPayload);

      return {
        requiresTwoFactor: true,
        temporaryToken,
        message: `2FA required. Code sent to your ${user.twoFactorMethod}.`,
      };
    }

    // If no 2FA, complete login immediately
    return this.completeLogin(user, loginDetails);
  }

  // Complete login after 2FA verification or when 2FA is not enabled
  private async completeLogin(user: User, loginDetails: any) {
    // Reset failed login attempts and update last login
    user.failedLoginAttempts = 0;
    user.accountLockedUntil = null;
    user.lastLogin = new Date();
    await this.userRepository.save(user);

    // Record successful login
    await this.securityAuditService.recordSecurityEvent({
      eventType: 'SUCCESSFUL_LOGIN',
      userId: user.userId,
      email: user.email,
      ipAddress: loginDetails.ip,
      userAgent: loginDetails.userAgent,
    });

    // Send login notification
    await this.sendLoginNotification(user, loginDetails);

    // Get user roles
    const userRoles = user.roles?.map((role) => role.roles) || [
      UserRoleType.USER,
    ];

    const payload = {
      userId: user.userId,
      id: user.id,
      email: user.email,
      username: user.username,
      roles: userRoles,
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneNoVerified,
    };

    return {
      accesstoken: this.jwtService.sign(payload),
      user: {
        userId: user.userId,
        username: user.username,
        email: user.email,
        roles: userRoles,
        emailVerified: user.emailVerified,
        phoneVerified: user.phoneNoVerified,
        isAccountActive: user.isAccountActive,
        completedTrades: user.completedTrades,
        details: user.details,
        is2FaEnabled: user.is2FaEnabled,
        twoFactorMethod: user.twoFactorMethod,
      },
    };
  }

  // New method to verify 2FA and complete login
  async verify2FAAndCompleteLogin(
    temporaryToken: string,
    twoFactorCode: string,
    loginDetails: any,
  ): Promise<{ accesstoken: string; user: any; message: string }> {
    try {
      // Verify temporary token
      const decoded = this.jwtService.verify(temporaryToken);

      if (decoded.purpose !== '2FA_VERIFICATION') {
        throw new UnauthorizedException('Invalid temporary token');
      }

      const user = await this.findOne(decoded.userId);

      if (!user.is2FaEnabled) {
        throw new BadRequestException('2FA is not enabled for this user');
      }

      // Verify 2FA code
      const is2FAValid = await this.verify2FACode(user.userId, twoFactorCode);

      if (!is2FAValid) {
        // Record failed 2FA attempt
        await this.securityAuditService.recordSecurityEvent({
          eventType: 'FAILED_2FA',
          reason: 'Invalid 2FA code',
          userId: user.userId,
          email: user.email,
          ipAddress: loginDetails.ip,
          userAgent: loginDetails.userAgent,
        });
        throw new UnauthorizedException('Invalid 2FA code');
      }

      // Record successful 2FA verification
      await this.securityAuditService.recordSecurityEvent({
        eventType: 'SUCCESSFUL_2FA',
        userId: user.userId,
        email: user.email,
        ipAddress: loginDetails.ip,
        userAgent: loginDetails.userAgent,
      });

      // Complete login process
      const loginResult = await this.completeLogin(user, loginDetails);

      return {
        ...loginResult,
        message: '2FA verified successfully. Login completed.',
      };
    } catch (error) {
      if (
        error.name === 'JsonWebTokenError' ||
        error.name === 'TokenExpiredError'
      ) {
        throw new UnauthorizedException('Invalid or expired temporary token');
      }
      throw error;
    }
  }

  // =============== SECURITY AUDIT METHODS ===============

  async getSecurityEvents(userId?: string, limit: number = 50) {
    return await this.securityAuditService.getSecurityEvents(userId, limit);
  }

  async getEventsByType(eventType: string, limit: number = 50) {
    return await this.securityAuditService.getEventsByType(eventType, limit);
  }

  async getEventsForDateRange(startDate: Date, endDate: Date, userId?: string) {
    return await this.securityAuditService.getEventsForDateRange(
      startDate,
      endDate,
      userId,
    );
  }

  // =============== NOTIFICATION METHODS ===============

  async getUserNotifications(userId: string, limit: number = 20) {
    return await this.notificationService.getUserNotifications(userId, limit);
  }

  async getUnreadNotifications(userId: string) {
    return await this.notificationService.getUnreadNotifications(userId);
  }

  async markNotificationAsRead(notificationId: string, userId: string) {
    // Verify the notification belongs to the user
    const notification = await this.notificationService.getUserNotifications(
      userId,
      100,
    );
    const userNotification = notification.find((n) => n.id === notificationId);

    if (!userNotification) {
      throw new NotFoundException(
        'Notification not found or does not belong to user',
      );
    }

    await this.notificationService.markNotificationAsRead(notificationId);
    return { message: 'Notification marked as read' };
  }

  async deleteNotification(notificationId: string, userId: string) {
    // Verify the notification belongs to the user
    const notification = await this.notificationService.getUserNotifications(
      userId,
      100,
    );
    const userNotification = notification.find((n) => n.id === notificationId);

    if (!userNotification) {
      throw new NotFoundException(
        'Notification not found or does not belong to user',
      );
    }

    await this.notificationService.deleteNotification(notificationId);
    return { message: 'Notification deleted successfully' };
  }

  async getAllNotifications(limit: number = 50) {
    // This would need to be implemented in the notification service
    // For now, return a placeholder
    return {
      message:
        'Admin notification retrieval - implement in notification service',
      limit,
    };
  }

  async broadcastNotification(
    title: string,
    message: string,
    type: string,
    priority: string,
    userIds?: string[],
  ) {
    let targetUsers: User[];

    if (userIds && userIds.length > 0) {
      // Send to specific users
      targetUsers = await this.userRepository.findByIds(userIds);
    } else {
      // Broadcast to all users
      targetUsers = await this.userRepository.find({
        select: ['userId', 'email'],
      });
    }

    const notifications = [];
    for (const user of targetUsers) {
      const notification =
        await this.notificationService.createAuthNotification(
          user.userId,
          user.email,
          title,
          message,
          type,
          priority,
        );
      notifications.push(notification);
    }

    return {
      message: `Notification sent to ${notifications.length} users`,
      count: notifications.length,
      notifications,
    };
  }

  // =============== ADVANCED SECURITY METHODS ===============

  async manualAccountLockout(
    userId: string,
    reason: string,
    duration?: number,
  ) {
    const user = await this.findOne(userId);
    const lockDuration = duration || 30; // Default 30 minutes

    user.accountLockedUntil = new Date(Date.now() + lockDuration * 60 * 1000);
    await this.userRepository.save(user);

    // Record security event
    await this.securityAuditService.recordSecurityEvent({
      eventType: 'MANUAL_LOCKOUT',
      reason: reason,
      userId: userId,
      email: user.email,
      additionalData: { lockDuration },
    });

    // Send notification
    await this.notificationService.createAuthNotification(
      userId,
      user.email,
      'Account Locked',
      `Your account has been locked by an administrator. Reason: ${reason}`,
      'SECURITY',
      'HIGH',
    );

    return {
      message: `Account locked for ${lockDuration} minutes`,
      lockedUntil: user.accountLockedUntil,
      reason,
    };
  }

  async unlockAccount(userId: string, reason: string) {
    const user = await this.findOne(userId);

    user.accountLockedUntil = null;
    user.failedLoginAttempts = 0;
    await this.userRepository.save(user);

    // Record security event
    await this.securityAuditService.recordSecurityEvent({
      eventType: 'MANUAL_UNLOCK',
      reason: reason,
      userId: userId,
      email: user.email,
    });

    // Send notification
    await this.notificationService.createAuthNotification(
      userId,
      user.email,
      'Account Unlocked',
      `Your account has been unlocked by an administrator. Reason: ${reason}`,
      'SECURITY',
      'MEDIUM',
    );

    return {
      message: 'Account unlocked successfully',
      reason,
    };
  }

  async getSuspiciousActivities(hours: number = 24) {
    const startDate = new Date(Date.now() - hours * 60 * 60 * 1000);

    // Get failed login attempts
    const failedLogins = await this.userRepository
      .createQueryBuilder('user')
      .where('user.failedLoginAttempts > :threshold', { threshold: 3 })
      .select([
        'user.userId',
        'user.email',
        'user.failedLoginAttempts',
        'user.accountLockedUntil',
      ])
      .getMany();

    // Get recently locked accounts
    const lockedAccounts = await this.userRepository
      .createQueryBuilder('user')
      .where('user.accountLockedUntil > :now', { now: new Date() })
      .select([
        'user.userId',
        'user.email',
        'user.accountLockedUntil',
        'user.failedLoginAttempts',
      ])
      .getMany();

    // Get security events for the period
    const securityEvents =
      await this.securityAuditService.getEventsForDateRange(
        startDate,
        new Date(),
      );

    return {
      failedLogins,
      lockedAccounts,
      securityEvents: securityEvents.filter((event) =>
        ['FAILED_LOGIN', 'ACCOUNT_LOCKED', 'SUSPICIOUS_ACTIVITY'].includes(
          event.eventType,
        ),
      ),
      analysisFor: `${hours} hours`,
      generatedAt: new Date(),
    };
  }

  async getFailedLoginPatterns() {
    // Get users with multiple failed attempts
    const patterns = await this.userRepository
      .createQueryBuilder('user')
      .where('user.failedLoginAttempts > 0')
      .select([
        'user.userId',
        'user.email',
        'user.failedLoginAttempts',
        'user.accountLockedUntil',
        'user.lastLogin',
      ])
      .orderBy('user.failedLoginAttempts', 'DESC')
      .limit(50)
      .getMany();

    // Group by attempt count
    const grouped = patterns.reduce((acc, user) => {
      const attempts = user.failedLoginAttempts;
      if (!acc[attempts]) {
        acc[attempts] = [];
      }
      acc[attempts].push(user);
      return acc;
    }, {});

    return {
      patterns: grouped,
      summary: {
        totalUsersWithFailedAttempts: patterns.length,
        highRiskUsers: patterns.filter((u) => u.failedLoginAttempts >= 5)
          .length,
        lockedUsers: patterns.filter(
          (u) => u.accountLockedUntil && new Date() < u.accountLockedUntil,
        ).length,
      },
      generatedAt: new Date(),
    };
  }

  // =============== THIRD PARTY AUTHENTICATION ===============

  async thirdPartyAuth(req: any): Promise<any> {
    try {
      const email = req.user?.email;
      const fullname = req.user?.name;
      const auth_provider = req.user?.authProvider;
      const profile_url = req.user?.image;

      if (!email) {
        throw new BadRequestException(
          'Email is required for third-party authentication',
        );
      }

      const userExists = await this.findByEmail(email);

      if (userExists) {
        // Check account status
        if (!userExists.isAccountActive) {
          return {
            statusCode: 401,
            message:
              'Account deactivated kindly contact admin to reactivate account',
          };
        }

        // Check for BTC wallet (assuming this is from your microservice architecture)
        // You might need to implement this based on your wallet service

        // Generate random profile image if user doesn't have one
        const profileImage =
          profile_url || generateRandomProfileImage(userExists.username);

        const tokenPayload = {
          userId: userExists.userId,
          userEmail: userExists.email,
          userName: userExists.username,
          iat: Math.floor(Date.now() / 1000),
          profile_url: profileImage,
          role: userExists.roles?.map((r) => r.roles) || ['user'],
        };

        // Send login notification
        await this.sendLoginNotification(userExists, {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
        });

        const token = this.jwtService.sign(tokenPayload);

        // Create notification for social login
        await this.notificationService.createAuthNotification(
          userExists.userId,
          userExists.email,
          'Social login successful',
          `You've successfully logged in with ${auth_provider}. Welcome back to XMOBIT!`,
          'auth',
          'low',
        );

        return {
          statusCode: 200,
          message: 'Login success. Redirecting...',
          data: token,
        };
      } else {
        // Register new user with social provider
        await this.registerUsersWithGoogleFacebook(
          email,
          auth_provider,
          fullname,
          profile_url,
        );

        const newUser = await this.findByEmail(email);
        const profileImage =
          profile_url || generateRandomProfileImage(newUser.username);

        const tokenPayload = {
          userId: newUser.userId,
          userEmail: newUser.email,
          userName: newUser.username,
          iat: Math.floor(Date.now() / 1000),
          profile_url: profileImage,
          role: newUser.roles?.map((r) => r.roles) || ['user'],
        };

        const token = this.jwtService.sign(tokenPayload);

        // Send signup confirmation
        await this.sendVerificationEmail(
          newUser.email,
          newUser.emailVerificationToken,
        );

        return {
          statusCode: 201,
          message: 'User registered.',
          data: token,
        };
      }
    } catch (error: any) {
      console.error('Error during third-party authentication:', error);
      return {
        statusCode: 500,
        message: error.message || 'Error during authentication',
        error: error.message,
      };
    }
  }

  async registerUsersWithGoogleFacebook(
    email: string,
    authProvider: string,
    fullname?: string,
    profileUrl?: string,
  ): Promise<User> {
    // Generate unique username for social login
    const randomUsername = await ensureUniqueUsername(this.userRepository);

    // Generate verification tokens
    const emailVerificationToken = randomBytes(32).toString('hex');
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 24);

    // Generate unique user ID
    const userId = uuidv4();

    // Get next ID from sequence
    const lastUser = await this.userRepository
      .createQueryBuilder('user')
      .orderBy('user.id', 'DESC')
      .getOne();
    const nextId = (lastUser?.id || 0) + 1;

    // Create user
    const user = this.userRepository.create({
      userId,
      id: nextId,
      username: randomUsername,
      email: email,
      password: 'SOCIAL_LOGIN', // No password for social login
      emailVerificationToken,
      emailVerificationExpires: tokenExpiry,
      dateRegistrated: new Date().toISOString(),
      authProvider: authProvider,
      emailVerified: true, // Social logins are pre-verified
      isVerified: true,
    });

    const savedUser = await this.userRepository.save(user);

    // Create default role
    const userRole = this.roleRepository.create({
      userId: savedUser.userId,
      roles: UserRoleType.USER,
    });
    await this.roleRepository.save(userRole);

    // Create user details if provided
    if (fullname) {
      const userDetails = this.detailsRepository.create({
        userId: savedUser.userId,
        fullname: fullname,
      });
      await this.detailsRepository.save(userDetails);
    }

    return savedUser;
  }

  // =============== SECURITY QUESTIONS METHODS ===============

  async setSecurityQuestion(
    userId: string,
    setSecurityQuestionDto: SetSecurityQuestionDto,
  ): Promise<{ message: string }> {
    const user = await this.findOne(userId);

    // Check if user already has a security question
    const existingQuestion = await this.securityQuestionRepository.findOne({
      where: { userId },
    });

    if (existingQuestion) {
      throw new BadRequestException(
        'Security question already set. Use update endpoint to change it.',
      );
    }

    // Hash the answer
    const answerHash = crypto
      .createHash('sha256')
      .update(setSecurityQuestionDto.answer.toLowerCase().trim())
      .digest('hex');

    const securityQuestion = this.securityQuestionRepository.create({
      userId,
      question: setSecurityQuestionDto.question,
      answerHash,
      isChanged: false,
    });

    await this.securityQuestionRepository.save(securityQuestion);

    // Record security event
    await this.securityAuditService.recordSecurityEvent({
      eventType: 'SECURITY_QUESTION_SET',
      userId: userId,
      email: user.email,
    });

    return { message: 'Security question set successfully' };
  }

  async verifySecurityQuestion(
    userId: string,
    verifySecurityQuestionDto: VerifySecurityQuestionDto,
  ): Promise<{ valid: boolean; message: string }> {
    const securityQuestion = await this.securityQuestionRepository.findOne({
      where: { userId },
    });

    if (!securityQuestion) {
      throw new NotFoundException('No security question found for this user');
    }

    // Hash the provided answer
    const providedAnswerHash = crypto
      .createHash('sha256')
      .update(verifySecurityQuestionDto.answer.toLowerCase().trim())
      .digest('hex');

    const isValid = providedAnswerHash === securityQuestion.answerHash;

    // Record security event
    await this.securityAuditService.recordSecurityEvent({
      eventType: isValid
        ? 'SECURITY_QUESTION_VERIFIED'
        : 'SECURITY_QUESTION_FAILED',
      userId: userId,
      email: (await this.findOne(userId)).email,
    });

    return {
      valid: isValid,
      message: isValid
        ? 'Security question verified successfully'
        : 'Invalid answer',
    };
  }

  async updateSecurityQuestion(
    userId: string,
    updateSecurityQuestionDto: UpdateSecurityQuestionDto,
  ): Promise<{ message: string }> {
    const user = await this.findOne(userId);
    const securityQuestion = await this.securityQuestionRepository.findOne({
      where: { userId },
    });

    if (!securityQuestion) {
      throw new NotFoundException('No security question found for this user');
    }

    if (securityQuestion.isChanged) {
      throw new BadRequestException(
        'Security question can only be changed once',
      );
    }

    // Verify current answer
    const currentAnswerHash = crypto
      .createHash('sha256')
      .update(updateSecurityQuestionDto.currentAnswer.toLowerCase().trim())
      .digest('hex');

    if (currentAnswerHash !== securityQuestion.answerHash) {
      throw new UnauthorizedException('Current answer is incorrect');
    }

    // Hash the new answer
    const newAnswerHash = crypto
      .createHash('sha256')
      .update(updateSecurityQuestionDto.newAnswer.toLowerCase().trim())
      .digest('hex');

    // Update the security question
    securityQuestion.question = updateSecurityQuestionDto.newQuestion;
    securityQuestion.answerHash = newAnswerHash;
    securityQuestion.isChanged = true;

    await this.securityQuestionRepository.save(securityQuestion);

    // Record security event
    await this.securityAuditService.recordSecurityEvent({
      eventType: 'SECURITY_QUESTION_UPDATED',
      userId: userId,
      email: user.email,
    });

    return {
      message:
        'Security question updated successfully. This was your one-time change.',
    };
  }

  async getSecurityQuestion(
    userId: string,
  ): Promise<{ question: string; isChanged: boolean }> {
    const securityQuestion = await this.securityQuestionRepository.findOne({
      where: { userId },
    });

    if (!securityQuestion) {
      throw new NotFoundException('No security question found for this user');
    }

    return {
      question: securityQuestion.question,
      isChanged: securityQuestion.isChanged,
    };
  }

  async deleteSecurityQuestion(userId: string): Promise<{ message: string }> {
    const user = await this.findOne(userId);
    const result = await this.securityQuestionRepository.delete({ userId });

    if (result.affected === 0) {
      throw new NotFoundException('No security question found for this user');
    }

    // Record security event
    await this.securityAuditService.recordSecurityEvent({
      eventType: 'SECURITY_QUESTION_DELETED',
      userId: userId,
      email: user.email,
    });
    return { message: 'Security question deleted successfully' };
  }
}
