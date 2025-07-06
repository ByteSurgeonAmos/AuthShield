import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  Query,
  UseGuards,
  Request,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
  ApiQuery,
  ApiBody,
  ApiSecurity,
} from '@nestjs/swagger';
import { UsersService } from './auth.service';
import { SimpleRegisterDto } from './dto/simple-register.dto';
import { CompleteProfileDto } from './dto/complete-profile.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { Setup2FADto, Verify2FADto, Disable2FADto } from './dto/setup-2fa.dto';
import { Verify2FALoginDto } from './dto/verify-2fa-login.dto';
import {
  SendEmailVerificationOTPDto,
  VerifyEmailOTPDto,
} from './dto/verify-email-otp.dto';
import { SendPhoneOTPDto, VerifyPhoneOTPDto } from './dto/phone-otp.dto';
import { AnalyticsQueryDto } from './dto/analytics.dto';
import {
  SetSecurityQuestionDto,
  VerifySecurityQuestionDto,
  UpdateSecurityQuestionDto,
} from './dto/security-question.dto';
import {
  LoginResponseDto,
  RegisterResponseDto,
  ProfileCompleteResponseDto,
  Setup2FAResponseDto,
  MessageResponseDto,
  BooleanResponseDto,
} from './dto/auth-response.dto';
import {
  UserProfileDto,
  AnalyticsResponseDto,
  SecurityAnalyticsDto,
  BulkActionResponseDto,
  NotificationDto,
} from './dto/response-models.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtAdminGuard } from './guards/jwt-admin.guard';
import { ApiKeyGuard } from './guards/api-key.guard';
import { JwtOrApiKeyGuard } from './guards/jwt-or-api-key.guard';
import { AdminOrApiKeyGuard } from './guards/admin-or-api-key.guard';
import { JwtAndApiKeyGuard } from './guards/jwt-and-api-key.guard';
import { AdminJwtAndApiKeyGuard } from './guards/admin-jwt-and-api-key.guard';
import { WalletValidationService } from './services/wallet-validation.service';

@ApiTags('Authentication')
@Controller('users')
export class UsersController {
  constructor(
    private readonly usersService: UsersService,
    private readonly walletValidationService: WalletValidationService,
  ) {}

  // =============== AUTHENTICATION ENDPOINTS ===============

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Register a new user',
    description:
      'Create a new user account with email, password, and full name only',
  })
  @ApiResponse({
    status: 201,
    description: 'User registered successfully',
    type: RegisterResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid input data',
  })
  @ApiResponse({
    status: 409,
    description: 'Conflict - Email already exists',
  })
  async create(@Body() createUserDto: SimpleRegisterDto) {
    return this.usersService.create(createUserDto);
  }

  @Patch('complete-profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Complete user profile',
    description:
      'Complete user profile with username and other optional details',
  })
  @ApiResponse({
    status: 200,
    description: 'Profile completed successfully',
    type: ProfileCompleteResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Username already exists',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid or missing token',
  })
  async completeProfile(
    @Request() req,
    @Body() completeProfileDto: CompleteProfileDto,
  ) {
    return this.usersService.completeProfile(
      req.user.userId,
      completeProfileDto,
    );
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Login user',
    description:
      'Authenticate user with email and password. May require 2FA verification.',
  })
  @ApiResponse({
    status: 200,
    description: 'Login successful or 2FA required',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid credentials',
  })
  @ApiResponse({
    status: 423,
    description: 'Locked - Account is locked',
  })
  async login(@Body() loginDto: LoginUserDto, @Request() req) {
    const loginDetails = {
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
    };
    return this.usersService.enhancedLogin(loginDto, loginDetails);
  }

  @Post('verify-2fa-login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify 2FA and complete login',
    description:
      'Complete login process by verifying two-factor authentication code',
  })
  @ApiResponse({
    status: 200,
    description: 'Login completed successfully',
    type: LoginResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid 2FA code',
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid temporary token',
  })
  async verify2FALogin(@Body() verifyDto: Verify2FALoginDto, @Request() req) {
    const loginDetails = {
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
    };
    return this.usersService.verify2FAAndCompleteLogin(
      verifyDto.temporaryToken,
      verifyDto.twoFactorCode,
      loginDetails,
    );
  }

  @Post('send-verification-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Send email verification OTP',
    description: 'Send a 6-digit OTP to user email for verification',
  })
  @ApiBody({
    type: SendEmailVerificationOTPDto,
  })
  @ApiResponse({
    status: 200,
    description: 'Verification OTP sent successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Email already verified or user not found',
  })
  async sendVerificationOTP(@Body() sendOtpDto: SendEmailVerificationOTPDto) {
    return this.usersService.sendEmailVerificationOTP(sendOtpDto.email);
  }

  @Post('verify-email-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify email using OTP',
    description: 'Verify user email address using 6-digit OTP code',
  })
  @ApiBody({
    type: VerifyEmailOTPDto,
  })
  @ApiResponse({
    status: 200,
    description: 'Email verified successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid or expired OTP',
  })
  async verifyEmailOTP(@Body() verifyOtpDto: VerifyEmailOTPDto) {
    return this.usersService.verifyEmailOTP(
      verifyOtpDto.email,
      verifyOtpDto.otp,
    );
  }

  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify email address (DEPRECATED)',
    description:
      'Legacy email verification using token - use OTP verification instead',
    deprecated: true,
  })
  @ApiQuery({
    name: 'token',
    description: 'Email verification token',
    example: 'abc123def456',
  })
  @ApiResponse({
    status: 200,
    description: 'Email verified successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid or expired token',
  })
  async verifyEmail(@Query('token') token: string) {
    return this.usersService.verifyEmail(token);
  }
  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Resend email verification OTP',
    description: 'Resend 6-digit OTP code to user email for verification',
  })
  @ApiBody({
    type: SendEmailVerificationOTPDto,
  })
  @ApiResponse({
    status: 200,
    description: 'Verification OTP sent',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @ApiResponse({
    status: 400,
    description: 'Email already verified',
  })
  async resendVerificationToken(
    @Body() sendOtpDto: SendEmailVerificationOTPDto,
  ) {
    return this.usersService.resendVerificationToken(sendOtpDto.email);
  }

  // =============== 2FA ENDPOINTS ===============

  @Post('setup-2fa')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @ApiTags('2FA')
  @ApiOperation({
    summary: 'Setup two-factor authentication',
    description: 'Initialize 2FA setup for user account',
  })
  @ApiResponse({
    status: 200,
    description: '2FA setup initiated',
    type: Setup2FAResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async setup2FA(@Request() req, @Body() setup2FADto: Setup2FADto) {
    return this.usersService.setup2FA(req.user.userId, setup2FADto.method);
  }

  @Post('verify-2fa-setup')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @ApiTags('2FA')
  @ApiOperation({
    summary: 'Verify 2FA setup',
    description: 'Complete 2FA setup by verifying the generated token',
  })
  @ApiResponse({
    status: 200,
    description: '2FA setup completed',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid verification token',
  })
  @HttpCode(HttpStatus.OK)
  async verify2FASetup(@Request() req, @Body() verifyDto: Verify2FADto) {
    return this.usersService.verify2FASetup(req.user.userId, verifyDto.token);
  }
  @Post('send-2fa-code')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @ApiTags('2FA')
  @ApiOperation({
    summary: 'Send 2FA code',
    description:
      'Send two-factor authentication code to user (for email/phone methods)',
  })
  @ApiResponse({
    status: 200,
    description: '2FA code sent successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async send2FACode(@Request() req) {
    return this.usersService.send2FACode(req.user.userId);
  }

  @Post('verify-2fa')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @ApiTags('2FA')
  @ApiOperation({
    summary: 'Verify 2FA code',
    description: 'Verify two-factor authentication code',
  })
  @ApiResponse({
    status: 200,
    description: '2FA verification result',
    type: BooleanResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async verify2FA(@Request() req, @Body() verifyDto: Verify2FADto) {
    const isValid = await this.usersService.verify2FACode(
      req.user.userId,
      verifyDto.token,
    );
    return {
      valid: isValid,
      message: isValid ? '2FA verified successfully' : 'Invalid 2FA code',
    };
  }

  @Post('disable-2fa')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @ApiTags('2FA')
  @ApiOperation({
    summary: 'Disable 2FA',
    description: 'Disable two-factor authentication for user account',
  })
  @ApiResponse({
    status: 200,
    description: '2FA disabled successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid password',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async disable2FA(@Request() req, @Body() disableDto: Disable2FADto) {
    return this.usersService.disable2FA(
      req.user.userId,
      disableDto.currentPassword,
    );
  }

  // =============== PHONE VERIFICATION ENDPOINTS ===============

  @Post('send-otp')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @ApiTags('Phone Verification')
  @ApiOperation({
    summary: 'Send OTP to phone',
    description: 'Send one-time password to user phone number for verification',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        phoneNumber: {
          type: 'string',
          example: '+1234567890',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'OTP sent successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async sendOTP(@Request() req, @Body('phoneNumber') phoneNumber: string) {
    await this.usersService.sendOTP(phoneNumber, req.user.userId);
    return { message: 'OTP sent successfully' };
  }

  @Post('verify-otp')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @HttpCode(HttpStatus.OK)
  @ApiTags('Phone Verification')
  @ApiOperation({
    summary: 'Verify phone OTP',
    description: 'Verify one-time password sent to phone number',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        otp: {
          type: 'string',
          example: '123456',
        },
      },
    },
  })
  @ApiResponse({
    status: 200,
    description: 'OTP verified successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid OTP',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async verifyOTP(@Request() req, @Body() body: { otp: string }) {
    return this.usersService.verifyOTP(body.otp, req.user.userId);
  }

  // =============== USER MANAGEMENT ENDPOINTS ===============

  @Get()
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('User Management')
  @ApiOperation({
    summary: 'Get all users',
    description: 'Retrieve all users (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of all users',
    type: [UserProfileDto],
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async findAll() {
    return this.usersService.findAll();
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('User Management')
  @ApiOperation({
    summary: 'Get current user profile',
    description: 'Retrieve current authenticated user profile',
  })
  @ApiResponse({
    status: 200,
    description: 'User profile data',
    type: UserProfileDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async getProfile(@Request() req) {
    const user = req.user;
    return this.usersService.findOne(req.user.userId);
  }

  @Get('security-question')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Get security question',
    description: "Retrieve the user's security question (without answer)",
  })
  @ApiResponse({
    status: 200,
    description: 'Security question details',
    schema: {
      type: 'object',
      properties: {
        question: {
          type: 'string',
          example: 'What was the name of your first pet?',
        },
        isChanged: { type: 'boolean', example: false },
      },
    },
  })
  @ApiResponse({
    status: 404,
    description: 'No security question set',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async getSecurityQuestion(@Request() req) {
    try {
      return await this.usersService.getSecurityQuestion(req.user.userId);
    } catch (error) {
      console.error('Service call failed:', error.message);
      console.error('Error stack:', error.stack);
      throw error;
    }
  }

  @Get(':id')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('User Management')
  @ApiOperation({
    summary: 'Get user by ID',
    description: 'Retrieve specific user by ID (Admin only)',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  @ApiResponse({
    status: 200,
    description: 'User profile data',
    type: UserProfileDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Patch('profile')
  @UseGuards(JwtAuthGuard)
  async updateProfile(@Request() req, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(req.user.userId, updateUserDto);
  }

  @Patch(':id')
  @UseGuards(ApiKeyGuard)
  async update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }
  @Delete(':id')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('User Management')
  @ApiOperation({
    summary: 'Delete user',
    description: 'Delete a user account permanently (Admin only)',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID to delete',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  @ApiResponse({
    status: 200,
    description: 'User deleted successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async remove(@Param('id') id: string) {
    await this.usersService.remove(id);
    return { message: 'User deleted successfully' };
  }

  // =============== ROLE MANAGEMENT ENDPOINTS ===============

  @Post(':id/assign-role')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Admin')
  @ApiOperation({
    summary: 'Assign role to user',
    description: 'Assign a specific role to a user (Admin only)',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        role: {
          type: 'string',
          enum: ['user', 'system', 'super_admin'],
          description: 'Role to assign',
          example: 'user',
        },
      },
      required: ['role'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Role assigned successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - User already has this role',
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @HttpCode(HttpStatus.OK)
  async assignRole(@Param('id') id: string, @Body('role') role: string) {
    return this.usersService.assignRole(id, role as any);
  }

  @Delete(':id/remove-role')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Admin')
  @ApiOperation({
    summary: 'Remove role from user',
    description: 'Remove a specific role from a user (Admin only)',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        role: {
          type: 'string',
          enum: ['user', 'system', 'super_admin'],
          description: 'Role to remove',
          example: 'user',
        },
      },
      required: ['role'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Role removed successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'Role not found for this user',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async removeRole(@Param('id') id: string, @Body('role') role: string) {
    return this.usersService.removeRole(id, role as any);
  }
  @Get('analytics/overview')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Analytics')
  @ApiOperation({
    summary: 'Get user analytics overview',
    description:
      'Retrieve comprehensive user analytics and statistics (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'User analytics data',
    type: AnalyticsResponseDto,
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getUserAnalytics(@Query() query: AnalyticsQueryDto) {
    return this.usersService.getUserAnalytics(query.timeframe || 'monthly');
  }

  @Get('analytics/logins')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Analytics')
  @ApiOperation({
    summary: 'Get login analytics',
    description: 'Retrieve login analytics and statistics (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'Login analytics data',
    type: AnalyticsResponseDto,
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getLoginAnalytics(@Query() query: AnalyticsQueryDto) {
    return this.usersService.getLoginAnalytics(query.timeframe || 'monthly');
  }

  @Get('analytics/security')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Analytics')
  @ApiOperation({
    summary: 'Get security analytics',
    description:
      'Retrieve security-related analytics and statistics (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'Security analytics data',
    type: SecurityAnalyticsDto,
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getSecurityAnalytics() {
    return this.usersService.getSecurityAnalytics();
  }

  @Get('analytics/dashboard')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Analytics')
  @ApiOperation({
    summary: 'Get dashboard analytics',
    description:
      'Retrieve comprehensive dashboard analytics combining all metrics (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'Dashboard analytics data',
    schema: {
      type: 'object',
      properties: {
        users: { type: 'object', description: 'User analytics' },
        logins: { type: 'object', description: 'Login analytics' },
        security: { type: 'object', description: 'Security analytics' },
        generated: { type: 'string', description: 'Timestamp of generation' },
      },
    },
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getDashboardAnalytics(@Query() query: AnalyticsQueryDto) {
    const [userAnalytics, loginAnalytics, securityAnalytics] =
      await Promise.all([
        this.usersService.getUserAnalytics(query.timeframe || 'monthly'),
        this.usersService.getLoginAnalytics(query.timeframe || 'monthly'),
        this.usersService.getSecurityAnalytics(),
      ]);

    return {
      users: userAnalytics,
      logins: loginAnalytics,
      security: securityAnalytics,
      generated: new Date(),
    };
  }
  // =============== ADMIN UTILITIES ===============

  @Post('bulk-actions/activate')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Admin')
  @ApiOperation({
    summary: 'Bulk activate users',
    description: 'Activate multiple user accounts simultaneously (Admin only)',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        userIds: {
          type: 'array',
          items: { type: 'string' },
          description: 'Array of user IDs to activate',
          example: ['user1', 'user2', 'user3'],
        },
      },
      required: ['userIds'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Bulk activation results',
    type: BulkActionResponseDto,
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @HttpCode(HttpStatus.OK)
  async bulkActivateUsers(@Body('userIds') userIds: string[]) {
    const results = [];
    for (const userId of userIds) {
      try {
        await this.usersService.update(userId, { isAccountActive: true });
        results.push({ userId, status: 'activated' });
      } catch (error) {
        results.push({ userId, status: 'failed', error: error.message });
      }
    }
    return { results };
  }

  @Post('bulk-actions/deactivate')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Admin')
  @ApiOperation({
    summary: 'Bulk deactivate users',
    description:
      'Deactivate multiple user accounts simultaneously (Admin only)',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        userIds: {
          type: 'array',
          items: { type: 'string' },
          description: 'Array of user IDs to deactivate',
          example: ['user1', 'user2', 'user3'],
        },
      },
      required: ['userIds'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Bulk deactivation results',
    type: BulkActionResponseDto,
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @HttpCode(HttpStatus.OK)
  async bulkDeactivateUsers(@Body('userIds') userIds: string[]) {
    const results = [];
    for (const userId of userIds) {
      try {
        await this.usersService.update(userId, { isAccountActive: false });
        results.push({ userId, status: 'deactivated' });
      } catch (error) {
        results.push({ userId, status: 'failed', error: error.message });
      }
    }
    return { results };
  }

  @Post('bulk-actions/reset-failed-attempts')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Admin')
  @ApiOperation({
    summary: 'Bulk reset failed login attempts',
    description:
      'Reset failed login attempts for multiple users simultaneously (Admin only)',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        userIds: {
          type: 'array',
          items: { type: 'string' },
          description: 'Array of user IDs to reset failed attempts for',
          example: ['user1', 'user2', 'user3'],
        },
      },
      required: ['userIds'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Bulk reset results',
    type: BulkActionResponseDto,
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @HttpCode(HttpStatus.OK)
  async bulkResetFailedAttempts(@Body('userIds') userIds: string[]) {
    const results = [];
    for (const userId of userIds) {
      try {
        await this.usersService.update(userId, {
          failedLoginAttempts: 0,
          accountLockedUntil: null,
        });
        results.push({ userId, status: 'reset' });
      } catch (error) {
        results.push({ userId, status: 'failed', error: error.message });
      }
    }
    return { results };
  }
  // =============== SEARCH AND FILTER ENDPOINTS ===============

  @Get('search/by-email')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  // @ApiTags('Admin')
  @ApiOperation({
    summary: 'Search user by email',
    description: 'Search for a user by email address (Admin only)',
  })
  @ApiQuery({
    name: 'email',
    description: 'Email address to search for',
    example: 'john.doe@example.com',
  })
  @ApiResponse({
    status: 200,
    description: 'User found',
    type: UserProfileDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async searchByEmail(@Query('email') email: string) {
    return this.usersService.findByEmail(email);
  }

  @Get('filter/unverified')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Admin')
  @ApiOperation({
    summary: 'Get unverified users',
    description: 'Retrieve users with unverified email addresses (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of unverified users',
    type: [UserProfileDto],
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getUnverifiedUsers() {
    return this.usersService
      .findAll()
      .then((users) => users.filter((user) => !user.emailVerified));
  }

  @Get('filter/locked')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Admin')
  @ApiOperation({
    summary: 'Get locked users',
    description: 'Retrieve users with locked accounts (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of locked users',
    type: [UserProfileDto],
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getLockedUsers() {
    return this.usersService
      .findAll()
      .then((users) =>
        users.filter(
          (user) =>
            user.accountLockedUntil && new Date() < user.accountLockedUntil,
        ),
      );
  }

  @Get('filter/inactive')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Admin')
  @ApiOperation({
    summary: 'Get inactive users',
    description: 'Retrieve users with inactive accounts (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of inactive users',
    type: [UserProfileDto],
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getInactiveUsers() {
    return this.usersService
      .findAll()
      .then((users) => users.filter((user) => !user.isAccountActive));
  }

  @Get('filter/2fa-enabled')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Admin')
  @ApiOperation({
    summary: 'Get 2FA enabled users',
    description:
      'Retrieve users with two-factor authentication enabled (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'List of users with 2FA enabled',
    type: [UserProfileDto],
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async get2FAEnabledUsers() {
    return this.usersService
      .findAll()
      .then((users) => users.filter((user) => user.is2FaEnabled));
  }
  // =============== SECURITY AUDIT ENDPOINTS ===============

  @Get('security/audit-logs')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Get security audit logs',
    description:
      'Retrieve security audit logs with optional filtering (Admin only)',
  })
  @ApiQuery({
    name: 'userId',
    description: 'Filter by user ID',
    required: false,
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  @ApiQuery({
    name: 'limit',
    description: 'Maximum number of logs to return',
    required: false,
    example: 50,
  })
  @ApiResponse({
    status: 200,
    description: 'Security audit logs',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          userId: { type: 'string' },
          eventType: { type: 'string' },
          eventDetails: { type: 'object' },
          timestamp: { type: 'string' },
          ipAddress: { type: 'string' },
          userAgent: { type: 'string' },
        },
      },
    },
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getSecurityAuditLogs(
    @Query('userId') userId?: string,
    @Query('limit') limit?: number,
  ) {
    return this.usersService.getSecurityEvents(
      userId,
      limit ? parseInt(limit.toString()) : 50,
    );
  }

  @Get('security/audit-logs/by-type/:eventType')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Get audit logs by event type',
    description:
      'Retrieve security audit logs filtered by event type (Admin only)',
  })
  @ApiParam({
    name: 'eventType',
    description: 'Type of security event',
    example: 'login_attempt',
  })
  @ApiQuery({
    name: 'limit',
    description: 'Maximum number of logs to return',
    required: false,
    example: 50,
  })
  @ApiResponse({
    status: 200,
    description: 'Filtered security audit logs',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getAuditLogsByType(
    @Param('eventType') eventType: string,
    @Query('limit') limit?: number,
  ) {
    return this.usersService.getEventsByType(
      eventType,
      limit ? parseInt(limit.toString()) : 50,
    );
  }

  @Get('security/audit-logs/date-range')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Get audit logs by date range',
    description:
      'Retrieve security audit logs within a specific date range (Admin only)',
  })
  @ApiQuery({
    name: 'startDate',
    description: 'Start date (ISO 8601 format)',
    example: '2024-01-01T00:00:00.000Z',
  })
  @ApiQuery({
    name: 'endDate',
    description: 'End date (ISO 8601 format)',
    example: '2024-12-31T23:59:59.999Z',
  })
  @ApiQuery({
    name: 'userId',
    description: 'Filter by user ID',
    required: false,
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  @ApiResponse({
    status: 200,
    description: 'Date-filtered security audit logs',
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid date format',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getAuditLogsByDateRange(
    @Query('startDate') startDate: string,
    @Query('endDate') endDate: string,
    @Query('userId') userId?: string,
  ) {
    return this.usersService.getEventsForDateRange(
      new Date(startDate),
      new Date(endDate),
      userId,
    );
  }

  @Get('profile/audit-logs')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Get user audit logs',
    description: 'Retrieve security audit logs for current user',
  })
  @ApiQuery({
    name: 'limit',
    description: 'Maximum number of logs to return',
    required: false,
    example: 20,
  })
  @ApiResponse({
    status: 200,
    description: 'User security audit logs',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async getUserAuditLogs(@Request() req, @Query('limit') limit?: number) {
    return this.usersService.getSecurityEvents(
      req.user.userId,
      limit ? parseInt(limit.toString()) : 20,
    );
  }
  // =============== NOTIFICATION ENDPOINTS ===============

  @Get('notifications')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Notifications')
  @ApiOperation({
    summary: 'Get user notifications',
    description: 'Retrieve notifications for current user',
  })
  @ApiQuery({
    name: 'limit',
    description: 'Maximum number of notifications to return',
    required: false,
    example: 20,
  })
  @ApiResponse({
    status: 200,
    description: 'User notifications',
    type: [NotificationDto],
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async getUserNotifications(@Request() req, @Query('limit') limit?: number) {
    return this.usersService.getUserNotifications(
      req.user.userId,
      limit ? parseInt(limit.toString()) : 20,
    );
  }

  @Get('notifications/unread')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Notifications')
  @ApiOperation({
    summary: 'Get unread notifications',
    description: 'Retrieve unread notifications for current user',
  })
  @ApiResponse({
    status: 200,
    description: 'Unread notifications',
    type: [NotificationDto],
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async getUnreadNotifications(@Request() req) {
    return this.usersService.getUnreadNotifications(req.user.userId);
  }

  @Patch('notifications/:id/read')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Notifications')
  @ApiOperation({
    summary: 'Mark notification as read',
    description: 'Mark a specific notification as read',
  })
  @ApiParam({
    name: 'id',
    description: 'Notification ID',
    example: 'notif_123456',
  })
  @ApiResponse({
    status: 200,
    description: 'Notification marked as read',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'Notification not found',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  @HttpCode(HttpStatus.OK)
  async markNotificationAsRead(@Param('id') id: string, @Request() req) {
    return this.usersService.markNotificationAsRead(id, req.user.userId);
  }

  @Delete('notifications/:id')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Notifications')
  @ApiOperation({
    summary: 'Delete notification',
    description: 'Delete a specific notification',
  })
  @ApiParam({
    name: 'id',
    description: 'Notification ID',
    example: 'notif_123456',
  })
  @ApiResponse({
    status: 200,
    description: 'Notification deleted',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'Notification not found',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  async deleteNotification(@Param('id') id: string, @Request() req) {
    return this.usersService.deleteNotification(id, req.user.userId);
  }

  @Get('admin/notifications/all')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Notifications')
  @ApiOperation({
    summary: 'Get all notifications',
    description: 'Retrieve all notifications in the system (Admin only)',
  })
  @ApiQuery({
    name: 'limit',
    description: 'Maximum number of notifications to return',
    required: false,
    example: 50,
  })
  @ApiResponse({
    status: 200,
    description: 'All notifications',
    type: [NotificationDto],
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getAllNotifications(@Query('limit') limit?: number) {
    return this.usersService.getAllNotifications(
      limit ? parseInt(limit.toString()) : 50,
    );
  }
  @Post('admin/notifications/broadcast')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Notifications')
  @ApiOperation({
    summary: 'Broadcast notification',
    description:
      'Send notification to multiple users or all users (Admin only)',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        title: {
          type: 'string',
          description: 'Notification title',
          example: 'System Maintenance',
        },
        message: {
          type: 'string',
          description: 'Notification message',
          example:
            'The system will be under maintenance from 2:00 AM to 4:00 AM UTC.',
        },
        type: {
          type: 'string',
          description: 'Notification type',
          example: 'info',
        },
        priority: {
          type: 'string',
          description: 'Notification priority',
          example: 'high',
        },
        userIds: {
          type: 'array',
          items: { type: 'string' },
          description:
            'Array of user IDs to send notification to (optional - if not provided, sends to all users)',
          example: ['user1', 'user2'],
        },
      },
      required: ['title', 'message', 'type', 'priority'],
    },
  })
  @ApiResponse({
    status: 201,
    description: 'Notification broadcasted successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @HttpCode(HttpStatus.CREATED)
  async broadcastNotification(
    @Body()
    body: {
      title: string;
      message: string;
      type: string;
      priority: string;
      userIds?: string[];
    },
  ) {
    return this.usersService.broadcastNotification(
      body.title,
      body.message,
      body.type,
      body.priority,
      body.userIds,
    );
  }
  // =============== ADVANCED SECURITY ENDPOINTS ===============

  @Post('security/manual-lockout/:id')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Manual account lockout',
    description:
      'Manually lock a user account for security reasons (Admin only)',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID to lock',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        reason: {
          type: 'string',
          description: 'Reason for account lockout',
          example: 'Suspicious activity detected',
        },
        duration: {
          type: 'number',
          description: 'Lockout duration in hours (optional)',
          example: 24,
        },
      },
      required: ['reason'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Account locked successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @HttpCode(HttpStatus.OK)
  async manualLockout(
    @Param('id') id: string,
    @Body() body: { reason: string; duration?: number },
  ) {
    return this.usersService.manualAccountLockout(
      id,
      body.reason,
      body.duration,
    );
  }

  @Post('security/unlock-account/:id')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Unlock account',
    description: 'Manually unlock a locked user account (Admin only)',
  })
  @ApiParam({
    name: 'id',
    description: 'User ID to unlock',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        reason: {
          type: 'string',
          description: 'Reason for unlocking account',
          example: 'Resolved security concerns',
        },
      },
      required: ['reason'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Account unlocked successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  @HttpCode(HttpStatus.OK)
  async unlockAccount(
    @Param('id') id: string,
    @Body() body: { reason: string },
  ) {
    return this.usersService.unlockAccount(id, body.reason);
  }
  @Get('security/suspicious-activities')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Get suspicious activities',
    description:
      'Retrieve suspicious security activities within specified time frame (Admin only)',
  })
  @ApiQuery({
    name: 'hours',
    description: 'Time frame in hours to analyze (default: 24)',
    required: false,
    example: 24,
  })
  @ApiResponse({
    status: 200,
    description: 'List of suspicious activities',
    schema: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          userId: { type: 'string' },
          activityType: { type: 'string' },
          timestamp: { type: 'string' },
          details: { type: 'object' },
          riskLevel: { type: 'string' },
        },
      },
    },
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getSuspiciousActivities(@Query('hours') hours?: number) {
    return this.usersService.getSuspiciousActivities(
      hours ? parseInt(hours.toString()) : 24,
    );
  }

  @Get('security/failed-login-patterns')
  @UseGuards(ApiKeyGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Get failed login patterns',
    description:
      'Analyze and retrieve failed login patterns for security analysis (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'Failed login patterns analysis',
    schema: {
      type: 'object',
      properties: {
        totalFailedAttempts: { type: 'number' },
        topFailedIPs: { type: 'array' },
        timePatterns: { type: 'object' },
        userPatterns: { type: 'object' },
      },
    },
  })
  @ApiResponse({
    status: 403,
    description: 'Forbidden - Admin access required',
  })
  async getFailedLoginPatterns() {
    return this.usersService.getFailedLoginPatterns();
  }
  // =============== SECURITY QUESTIONS ENDPOINTS ===============

  @Post('security-question/set')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Set security question',
    description: 'Set a security question and answer for account recovery',
  })
  @ApiResponse({
    status: 201,
    description: 'Security question set successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid question or answer',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  @HttpCode(HttpStatus.CREATED)
  async setSecurityQuestion(
    @Request() req,
    @Body() setSecurityQuestionDto: SetSecurityQuestionDto,
  ) {
    return this.usersService.setSecurityQuestion(
      req.user.userId,
      setSecurityQuestionDto,
    );
  }

  @Post('security-question/verify')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Verify security question',
    description: "Verify the answer to the user's security question",
  })
  @ApiResponse({
    status: 200,
    description: 'Security question verification result',
    type: BooleanResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid answer',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  @HttpCode(HttpStatus.OK)
  async verifySecurityQuestion(
    @Request() req,
    @Body() verifySecurityQuestionDto: VerifySecurityQuestionDto,
  ) {
    return this.usersService.verifySecurityQuestion(
      req.user.userId,
      verifySecurityQuestionDto,
    );
  }

  @Patch('security-question/update')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Update security question',
    description:
      'Update the security question and answer (requires current answer verification)',
  })
  @ApiResponse({
    status: 200,
    description: 'Security question updated successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Bad request - Invalid current answer',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  @HttpCode(HttpStatus.OK)
  async updateSecurityQuestion(
    @Request() req,
    @Body() updateSecurityQuestionDto: UpdateSecurityQuestionDto,
  ) {
    return this.usersService.updateSecurityQuestion(
      req.user.userId,
      updateSecurityQuestionDto,
    );
  }

  @Delete('security-question')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiTags('Security')
  @ApiOperation({
    summary: 'Delete security question',
    description: "Remove the user's security question and answer",
  })
  @ApiResponse({
    status: 200,
    description: 'Security question deleted successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'No security question to delete',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Invalid token',
  })
  @HttpCode(HttpStatus.OK)
  async deleteSecurityQuestion(@Request() req) {
    return this.usersService.deleteSecurityQuestion(req.user.userId);
  }

  // =============== TOKEN VERIFICATION ENDPOINT ===============

  @Post('verify-token')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Verify JWT token',
    description:
      'Verify the validity of a JWT token and return user information',
  })
  @ApiResponse({
    status: 200,
    description: 'Token is valid',
    type: UserProfileDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid or expired token',
  })
  async verifyToken(@Request() req) {
    const authHeader = req.headers.authorization;
    return this.usersService.verifyTokenValidity(authHeader);
  }

  @Post('resend-email-otp')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Resend email verification OTP',
    description: 'Resend verification OTP to user email',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          format: 'email',
          example: 'user@example.com',
        },
      },
      required: ['email'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'OTP sent successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 404,
    description: 'User not found',
  })
  async resendEmailOTP(@Body() body: { email: string }) {
    return this.usersService.resendVerificationToken(body.email);
  }

  // =============== PHONE VERIFICATION ENDPOINTS ===============

  @Post('send-phone-otp')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Send phone verification OTP',
    description: 'Send OTP to user phone number for verification',
  })
  @ApiResponse({
    status: 200,
    description: 'Phone OTP sent successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized',
  })
  async sendPhoneOTP(@Request() req, @Body() sendPhoneOTPDto: SendPhoneOTPDto) {
    return this.usersService.sendPhoneOTP(
      req.user.userId,
      sendPhoneOTPDto.phoneNumber,
      sendPhoneOTPDto.countryCode,
    );
  }

  @Post('verify-phone-otp')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Verify phone OTP',
    description: 'Verify phone number using OTP code',
  })
  @ApiResponse({
    status: 200,
    description: 'Phone verified successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid OTP code',
  })
  async verifyPhoneOTP(
    @Request() req,
    @Body() verifyPhoneOTPDto: VerifyPhoneOTPDto,
  ) {
    return this.usersService.verifyPhoneOTP(
      req.user.userId,
      verifyPhoneOTPDto.phoneNumber,
      verifyPhoneOTPDto.otpCode,
      verifyPhoneOTPDto.countryCode,
    );
  }

  // =============== PASSWORD RESET ENDPOINTS ===============

  @Post('request-password-reset')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Request password reset',
    description: 'Send password reset email to user',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          format: 'email',
          example: 'user@example.com',
        },
      },
      required: ['email'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Password reset email sent',
    type: MessageResponseDto,
  })
  async requestPasswordReset(@Body() body: { email: string }) {
    return this.usersService.requestPasswordReset(body.email);
  }

  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Reset password',
    description: 'Reset user password using reset token',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        token: {
          type: 'string',
          example: 'reset-token-here',
        },
        newPassword: {
          type: 'string',
          minLength: 8,
          example: 'NewSecurePassword123!',
        },
      },
      required: ['token', 'newPassword'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Password reset successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Invalid or expired token',
  })
  async resetPassword(@Body() body: { token: string; newPassword: string }) {
    return this.usersService.resetPassword(body.token, body.newPassword);
  }

  @Post('change-password')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Change password',
    description: 'Change user password (requires current password)',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        currentPassword: {
          type: 'string',
          example: 'CurrentPassword123!',
        },
        newPassword: {
          type: 'string',
          minLength: 8,
          example: 'NewSecurePassword123!',
        },
      },
      required: ['currentPassword', 'newPassword'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Password changed successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Incorrect current password',
  })
  async changePassword(
    @Request() req,
    @Body() body: { currentPassword: string; newPassword: string },
  ) {
    return this.usersService.changePassword(
      req.user.userId,
      body.currentPassword,
      body.newPassword,
    );
  }

  // =============== THIRD PARTY AUTH ENDPOINT ===============

  @Post('third-party-auth')
  @HttpCode(HttpStatus.OK)
  @UseGuards(ApiKeyGuard)
  // @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Link third party authentication',
    description: 'Link third party provider account to user account',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          format: 'email',
          example: 'amos@email.com',
        },
        image: {
          type: 'string',
          format: 'uri',
          example: 'https://example.com/image.jpg',
        },
        name: {
          type: 'string',
          example: 'Amos Smith',
        },
        authProvider: {
          type: 'string',
          // enum: ['google', 'facebook', 'github'],
          example: 'google',
        },
      },
      required: ['email', 'image', 'name', 'authProvider'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Third party account linked successfully',
    type: MessageResponseDto,
  })
  async linkThirdPartyAuth(
    // @Request() req,
    @Body()
    body: {
      email: string;
      image: string;
      name: string;
      authProvider: string;
    },
  ) {
    return this.usersService.thirdPartyAuth(body);
  }

  // =============== PAYMENT DETAILS ENDPOINTS ===============

  @Post('payment-details')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Save payment details',
    description: 'Save user payment details',
  })
  @ApiResponse({
    status: 200,
    description: 'Payment details saved successfully',
    type: MessageResponseDto,
  })
  async savePaymentDetails(@Request() req, @Body() paymentData: any) {
    return this.usersService.savePaymentDetails(req.user.userId, paymentData);
  }

  @Get('payment-details')
  @HttpCode(HttpStatus.OK)
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Get payment details',
    description: 'Retrieve user payment details',
  })
  @ApiResponse({
    status: 200,
    description: 'Payment details retrieved successfully',
  })
  async getPaymentDetails(@Request() req) {
    return this.usersService.getPaymentDetails(req.user.userId);
  }

  // =============== SECURITY QUESTIONS ENDPOINTS ===============

  @Get('security-question')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get security question by email',
    description: 'Retrieve security question for password reset flow',
  })
  @ApiQuery({
    name: 'email',
    description: 'User email address',
    example: 'user@example.com',
  })
  @ApiResponse({
    status: 200,
    description: 'Security question retrieved successfully',
  })
  @ApiResponse({
    status: 404,
    description: 'User or security question not found',
  })
  async getSecurityQuestionByEmail(@Query('email') email: string) {
    return this.usersService.getSecurityQuestionByEmail(email);
  }

  @Post('verify-security-answer')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify security question answer',
    description: 'Verify security question answer for password reset flow',
  })
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          format: 'email',
          example: 'user@example.com',
        },
        answer: {
          type: 'string',
          example: 'Security answer',
        },
      },
      required: ['email', 'answer'],
    },
  })
  @ApiResponse({
    status: 200,
    description: 'Security answer verified successfully',
    type: MessageResponseDto,
  })
  @ApiResponse({
    status: 400,
    description: 'Incorrect security answer',
  })
  async verifySecurityAnswer(@Body() body: { email: string; answer: string }) {
    return this.usersService.verifySecurityAnswer(body.email, body.answer);
  }

  // =============== HEALTH CHECK ENDPOINT ===============

  @Get('health')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Health check',
    description: 'Check if the auth service is running',
  })
  @ApiResponse({
    status: 200,
    description: 'Service is healthy',
  })
  async healthCheck() {
    return {
      status: 'ok',
      timestamp: new Date().toISOString(),
      service: 'AuthShield',
    };
  }

  // =============== API KEY TEST ENDPOINT ===============

  @Get('test/api-key')
  @UseGuards(ApiKeyGuard)
  @ApiSecurity('api-key')
  @ApiTags('System')
  @ApiOperation({
    summary: 'Test API key authentication',
    description: 'Test endpoint to verify API key authentication is working',
  })
  @ApiResponse({
    status: 200,
    description: 'API key authentication successful',
  })
  @ApiResponse({
    status: 401,
    description: 'Invalid or missing API key',
  })
  async testApiKey() {
    return {
      status: 'success',
      message: 'API key authentication is working correctly',
      timestamp: new Date().toISOString(),
      service: 'AuthShield',
    };
  }

  // =============== WALLET VALIDATION ENDPOINTS ===============

  @Post('validate-wallets')
  @UseGuards(JwtAdminGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Manually trigger wallet validation',
    description:
      'Validate all user wallets and create missing ones (Admin only)',
  })
  @ApiQuery({
    name: 'userId',
    required: false,
    description: 'Optional user ID to validate specific user wallets',
  })
  @ApiResponse({
    status: 200,
    description: 'Wallet validation completed successfully',
  })
  @ApiResponse({
    status: 401,
    description: 'Unauthorized - Admin access required',
  })
  async validateWallets(@Query('userId') userId?: string): Promise<any> {
    return await this.walletValidationService.manualWalletValidation(userId);
  }

  @Get('wallet-validation/status')
  @UseGuards(JwtAdminGuard)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Get wallet validation cron job status',
    description:
      'Get information about the wallet validation cron job (Admin only)',
  })
  @ApiResponse({
    status: 200,
    description: 'Cron job information retrieved successfully',
  })
  async getWalletValidationStatus(): Promise<any> {
    return this.walletValidationService.getCronJobInfo();
  }
}
