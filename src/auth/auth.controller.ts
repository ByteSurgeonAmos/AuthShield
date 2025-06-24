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
import { UsersService } from './auth.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { LoginUserDto } from './dto/login-user.dto';
import { Setup2FADto, Verify2FADto, Disable2FADto } from './dto/setup-2fa.dto';
import { Verify2FALoginDto } from './dto/verify-2fa-login.dto';
import { AnalyticsQueryDto } from './dto/analytics.dto';
import {
  SetSecurityQuestionDto,
  VerifySecurityQuestionDto,
  UpdateSecurityQuestionDto,
} from './dto/security-question.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtAdminGuard } from './guards/jwt-admin.guard';

@Controller('users')
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  async create(@Body() createUserDto: CreateUserDto) {
    return this.usersService.create(createUserDto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  async login(@Body() loginDto: LoginUserDto, @Request() req) {
    const loginDetails = {
      ip: req.ip || req.connection.remoteAddress,
      userAgent: req.get('User-Agent'),
    };
    return this.usersService.enhancedLogin(loginDto, loginDetails);
  }

  @Post('verify-2fa-login')
  @HttpCode(HttpStatus.OK)
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

  @Post('verify-email')
  @HttpCode(HttpStatus.OK)
  async verifyEmail(@Query('token') token: string) {
    return this.usersService.verifyEmail(token);
  }

  @Post('resend-verification')
  @HttpCode(HttpStatus.OK)
  async resendVerificationToken(@Body('email') email: string) {
    return this.usersService.resendVerificationToken(email);
  }

  @Post('setup-2fa')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async setup2FA(@Request() req, @Body() setup2FADto: Setup2FADto) {
    return this.usersService.setup2FA(req.user.userId, setup2FADto.method);
  }

  @Post('verify-2fa-setup')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async verify2FASetup(@Request() req, @Body() verifyDto: Verify2FADto) {
    return this.usersService.verify2FASetup(req.user.userId, verifyDto.token);
  }

  @Post('send-2fa-code')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async send2FACode(@Request() req) {
    return this.usersService.send2FACode(req.user.userId);
  }

  @Post('verify-2fa')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
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
  @HttpCode(HttpStatus.OK)
  async disable2FA(@Request() req, @Body() disableDto: Disable2FADto) {
    return this.usersService.disable2FA(
      req.user.userId,
      disableDto.currentPassword,
    );
  }

  @Post('send-otp')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async sendOTP(@Request() req, @Body('phoneNumber') phoneNumber: string) {
    await this.usersService.sendOTP(phoneNumber, req.user.userId);
    return { message: 'OTP sent successfully' };
  }

  @Post('verify-otp')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async verifyOTP(@Request() req, @Body() body: { otp: string }) {
    return this.usersService.verifyOTP(body.otp, req.user.userId);
  }

  @Get()
  @UseGuards(JwtAdminGuard)
  async findAll() {
    return this.usersService.findAll();
  }

  @Get('profile')
  @UseGuards(JwtAuthGuard)
  async getProfile(@Request() req) {
    return this.usersService.findOne(req.user.userId);
  }

  @Get(':id')
  @UseGuards(JwtAdminGuard)
  async findOne(@Param('id') id: string) {
    return this.usersService.findOne(id);
  }

  @Patch('profile')
  @UseGuards(JwtAuthGuard)
  async updateProfile(@Request() req, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(req.user.userId, updateUserDto);
  }

  @Patch(':id')
  @UseGuards(JwtAdminGuard)
  async update(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto) {
    return this.usersService.update(id, updateUserDto);
  }

  @Delete(':id')
  @UseGuards(JwtAdminGuard)
  async remove(@Param('id') id: string) {
    await this.usersService.remove(id);
    return { message: 'User deleted successfully' };
  }

  // =============== ROLE MANAGEMENT ENDPOINTS ===============

  @Post(':id/assign-role')
  @UseGuards(JwtAdminGuard)
  @HttpCode(HttpStatus.OK)
  async assignRole(@Param('id') id: string, @Body('role') role: string) {
    return this.usersService.assignRole(id, role as any);
  }

  @Delete(':id/remove-role')
  @UseGuards(JwtAdminGuard)
  async removeRole(@Param('id') id: string, @Body('role') role: string) {
    return this.usersService.removeRole(id, role as any);
  }

  @Get('analytics/overview')
  @UseGuards(JwtAdminGuard)
  async getUserAnalytics(@Query() query: AnalyticsQueryDto) {
    return this.usersService.getUserAnalytics(query.timeframe || 'monthly');
  }

  @Get('analytics/logins')
  @UseGuards(JwtAdminGuard)
  async getLoginAnalytics(@Query() query: AnalyticsQueryDto) {
    return this.usersService.getLoginAnalytics(query.timeframe || 'monthly');
  }

  @Get('analytics/security')
  @UseGuards(JwtAdminGuard)
  async getSecurityAnalytics() {
    return this.usersService.getSecurityAnalytics();
  }

  @Get('analytics/dashboard')
  @UseGuards(JwtAdminGuard)
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
  @UseGuards(JwtAdminGuard)
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
  @UseGuards(JwtAdminGuard)
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
  @UseGuards(JwtAdminGuard)
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
  @UseGuards(JwtAdminGuard)
  async searchByEmail(@Query('email') email: string) {
    return this.usersService.findByEmail(email);
  }

  @Get('filter/unverified')
  @UseGuards(JwtAdminGuard)
  async getUnverifiedUsers() {
    return this.usersService
      .findAll()
      .then((users) => users.filter((user) => !user.emailVerified));
  }

  @Get('filter/locked')
  @UseGuards(JwtAdminGuard)
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
  @UseGuards(JwtAdminGuard)
  async getInactiveUsers() {
    return this.usersService
      .findAll()
      .then((users) => users.filter((user) => !user.isAccountActive));
  }

  @Get('filter/2fa-enabled')
  @UseGuards(JwtAdminGuard)
  async get2FAEnabledUsers() {
    return this.usersService
      .findAll()
      .then((users) => users.filter((user) => user.is2FaEnabled));
  }

  // =============== SECURITY AUDIT ENDPOINTS ===============

  @Get('security/audit-logs')
  @UseGuards(JwtAdminGuard)
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
  @UseGuards(JwtAdminGuard)
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
  @UseGuards(JwtAdminGuard)
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
  async getUserAuditLogs(@Request() req, @Query('limit') limit?: number) {
    return this.usersService.getSecurityEvents(
      req.user.userId,
      limit ? parseInt(limit.toString()) : 20,
    );
  }

  // =============== NOTIFICATION ENDPOINTS ===============

  @Get('notifications')
  @UseGuards(JwtAuthGuard)
  async getUserNotifications(@Request() req, @Query('limit') limit?: number) {
    return this.usersService.getUserNotifications(
      req.user.userId,
      limit ? parseInt(limit.toString()) : 20,
    );
  }

  @Get('notifications/unread')
  @UseGuards(JwtAuthGuard)
  async getUnreadNotifications(@Request() req) {
    return this.usersService.getUnreadNotifications(req.user.userId);
  }

  @Patch('notifications/:id/read')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async markNotificationAsRead(@Param('id') id: string, @Request() req) {
    return this.usersService.markNotificationAsRead(id, req.user.userId);
  }

  @Delete('notifications/:id')
  @UseGuards(JwtAuthGuard)
  async deleteNotification(@Param('id') id: string, @Request() req) {
    return this.usersService.deleteNotification(id, req.user.userId);
  }

  @Get('admin/notifications/all')
  @UseGuards(JwtAdminGuard)
  async getAllNotifications(@Query('limit') limit?: number) {
    return this.usersService.getAllNotifications(
      limit ? parseInt(limit.toString()) : 50,
    );
  }

  @Post('admin/notifications/broadcast')
  @UseGuards(JwtAdminGuard)
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
  @UseGuards(JwtAdminGuard)
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
  @UseGuards(JwtAdminGuard)
  @HttpCode(HttpStatus.OK)
  async unlockAccount(
    @Param('id') id: string,
    @Body() body: { reason: string },
  ) {
    return this.usersService.unlockAccount(id, body.reason);
  }

  @Get('security/suspicious-activities')
  @UseGuards(JwtAdminGuard)
  async getSuspiciousActivities(@Query('hours') hours?: number) {
    return this.usersService.getSuspiciousActivities(
      hours ? parseInt(hours.toString()) : 24,
    );
  }
  @Get('security/failed-login-patterns')
  @UseGuards(JwtAdminGuard)
  async getFailedLoginPatterns() {
    return this.usersService.getFailedLoginPatterns();
  }

  // =============== SECURITY QUESTIONS ENDPOINTS ===============

  @Post('security-question/set')
  @UseGuards(JwtAuthGuard)
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

  @Get('security-question')
  @UseGuards(JwtAuthGuard)
  async getSecurityQuestion(@Request() req) {
    return this.usersService.getSecurityQuestion(req.user.userId);
  }

  @Delete('security-question')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  async deleteSecurityQuestion(@Request() req) {
    return this.usersService.deleteSecurityQuestion(req.user.userId);
  }
}
