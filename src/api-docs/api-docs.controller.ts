import { Controller, Get } from '@nestjs/common';

@Controller('api-docs')
export class ApiDocsController {
  @Get()
  getApiDocumentation() {
    return {
      title: 'User Management Microservice API',
      version: '1.0.0',
      description: 'Comprehensive user authentication and management system',
      baseUrl: '/api/v1',
      endpoints: {
        authentication: {
          'POST /users/register': {
            description: 'Register a new user',
            body: {
              username: 'string',
              email: 'string',
              password: 'string',
              phoneNumber: 'string (optional)',
              countryCode: 'string (optional)',
              fullname: 'string (optional)',
              country: 'string (optional)',
            },
            response: {
              userId: 'string',
              username: 'string',
              email: 'string',
              message: 'string',
            },
          },
          'POST /users/login': {
            description: 'Login user with optional 2FA',
            body: {
              email: 'string',
              password: 'string',
              twoFactorToken: 'string (optional)',
            },
            response: {
              accesstoken: 'string (if successful)',
              user: 'object (if successful)',
              requiresTwoFactor: 'boolean (if 2FA required)',
              message: 'string',
            },
          },
          'POST /users/verify-email': {
            description: 'Verify email with token',
            query: { token: 'string' },
            response: { message: 'string' },
          },
          'POST /users/resend-verification': {
            description: 'Resend email verification',
            body: { email: 'string' },
            response: { message: 'string' },
          },
        },
        twoFactorAuth: {
          'POST /users/setup-2fa': {
            description: 'Setup 2FA (email, phone, or authenticator)',
            headers: { Authorization: 'Bearer <token>' },
            body: { method: 'email | phone | authenticator' },
            response: {
              message: 'string',
              secret: 'string (for authenticator)',
              qrCode: 'string (for authenticator)',
            },
          },
          'POST /users/verify-2fa-setup': {
            description: 'Verify 2FA setup',
            headers: { Authorization: 'Bearer <token>' },
            body: { token: 'string' },
            response: { message: 'string' },
          },
          'POST /users/send-2fa-code': {
            description: 'Send 2FA code (for email/phone methods)',
            headers: { Authorization: 'Bearer <token>' },
            response: { message: 'string' },
          },
          'POST /users/verify-2fa': {
            description: 'Verify 2FA code',
            headers: { Authorization: 'Bearer <token>' },
            body: { token: 'string' },
            response: { valid: 'boolean', message: 'string' },
          },
          'POST /users/disable-2fa': {
            description: 'Disable 2FA',
            headers: { Authorization: 'Bearer <token>' },
            body: { currentPassword: 'string' },
            response: { message: 'string' },
          },
        },
        phoneVerification: {
          'POST /users/send-otp': {
            description: 'Send OTP to phone number',
            headers: { Authorization: 'Bearer <token>' },
            body: { phoneNumber: 'string' },
            response: { message: 'string' },
          },
          'POST /users/verify-otp': {
            description: 'Verify phone OTP',
            headers: { Authorization: 'Bearer <token>' },
            body: { otp: 'string' },
            response: { message: 'string' },
          },
        },
        userManagement: {
          'GET /users': {
            description: 'Get all users (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            response: 'Array of user objects',
          },
          'GET /users/profile': {
            description: 'Get current user profile',
            headers: { Authorization: 'Bearer <token>' },
            response: 'User object with details and roles',
          },
          'GET /users/:id': {
            description: 'Get user by ID (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            response: 'User object',
          },
          'PATCH /users/profile': {
            description: 'Update current user profile',
            headers: { Authorization: 'Bearer <token>' },
            body: 'Partial user update object',
            response: 'Updated user object',
          },
          'PATCH /users/:id': {
            description: 'Update user by ID (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            body: 'Partial user update object',
            response: 'Updated user object',
          },
          'DELETE /users/:id': {
            description: 'Delete user (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            response: { message: 'string' },
          },
        },
        roleManagement: {
          'POST /users/:id/assign-role': {
            description: 'Assign role to user (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            body: { role: 'user | system | super_admin' },
            response: { message: 'string' },
          },
          'DELETE /users/:id/remove-role': {
            description: 'Remove role from user (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            body: { role: 'user | system | super_admin' },
            response: { message: 'string' },
          },
        },
        analytics: {
          'GET /users/analytics/overview': {
            description: 'Get user analytics overview (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            query: { timeframe: 'daily | weekly | monthly | yearly' },
            response: {
              summary: 'Object with user counts',
              authProviders: 'Array of auth provider stats',
              usersByCountry: 'Array of country stats',
            },
          },
          'GET /users/analytics/logins': {
            description: 'Get login analytics (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            query: { timeframe: 'daily | weekly | monthly | yearly' },
            response: {
              recentLogins: 'number',
              totalFailedAttempts: 'number',
              lockedAccounts: 'number',
            },
          },
          'GET /users/analytics/security': {
            description: 'Get security analytics (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            response: {
              twoFAStats: 'Array of 2FA method stats',
              unverifiedUsers: 'number',
              inactiveUsers: 'number',
              securityScore: 'number (0-100)',
            },
          },
          'GET /users/analytics/dashboard': {
            description: 'Get comprehensive dashboard analytics (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            query: { timeframe: 'daily | weekly | monthly | yearly' },
            response: {
              users: 'User analytics object',
              logins: 'Login analytics object',
              security: 'Security analytics object',
              generated: 'timestamp',
            },
          },
        },
        adminUtilities: {
          'POST /users/bulk-actions/activate': {
            description: 'Bulk activate users (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            body: { userIds: 'Array of user IDs' },
            response: { results: 'Array of operation results' },
          },
          'POST /users/bulk-actions/deactivate': {
            description: 'Bulk deactivate users (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            body: { userIds: 'Array of user IDs' },
            response: { results: 'Array of operation results' },
          },
          'POST /users/bulk-actions/reset-failed-attempts': {
            description: 'Bulk reset failed login attempts (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            body: { userIds: 'Array of user IDs' },
            response: { results: 'Array of operation results' },
          },
        },
        searchAndFilter: {
          'GET /users/search/by-email': {
            description: 'Search user by email (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            query: { email: 'string' },
            response: 'User object or null',
          },
          'GET /users/filter/unverified': {
            description: 'Get unverified users (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            response: 'Array of unverified users',
          },
          'GET /users/filter/locked': {
            description: 'Get locked users (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            response: 'Array of locked users',
          },
          'GET /users/filter/inactive': {
            description: 'Get inactive users (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            response: 'Array of inactive users',
          },
          'GET /users/filter/2fa-enabled': {
            description: 'Get users with 2FA enabled (Admin only)',
            headers: { Authorization: 'Bearer <admin-token>' },
            response: 'Array of users with 2FA enabled',
          },
        },
      },
      healthChecks: {
        'GET /health': 'Service health check',
        'GET /health/ready': 'Service readiness check',
        'GET /health/live': 'Service liveness check',
      },
      errorCodes: {
        400: 'Bad Request - Invalid input data',
        401: 'Unauthorized - Invalid or missing token',
        403: 'Forbidden - Insufficient permissions',
        404: 'Not Found - Resource not found',
        409: 'Conflict - Resource already exists',
        429: 'Too Many Requests - Rate limit exceeded',
        500: 'Internal Server Error - Server error',
      },
      authenticationFlow: {
        step1: 'POST /users/register - Register new user',
        step2: 'Check email for verification link',
        step3: 'POST /users/verify-email?token=xxx - Verify email',
        step4: 'POST /users/login - Login with credentials',
        step5: 'If 2FA enabled, POST /users/verify-2fa with token',
        step6:
          'Use returned JWT token in Authorization header for authenticated requests',
      },
      twoFactorSetup: {
        step1:
          'POST /users/setup-2fa - Choose method (email/phone/authenticator)',
        step2: 'For authenticator: Scan QR code with authenticator app',
        step3: 'POST /users/verify-2fa-setup - Verify with generated token',
        step4: '2FA is now enabled for login',
      },
    };
  }

  @Get('postman')
  getPostmanCollection() {
    return {
      info: {
        name: 'User Management Microservice',
        description: 'API collection for user management microservice',
        version: '1.0.0',
      },
      baseUrl: '{{baseUrl}}/api/v1',
      auth: {
        type: 'bearer',
        bearer: [{ key: 'token', value: '{{authToken}}', type: 'string' }],
      },
      variables: [
        { key: 'baseUrl', value: 'http://localhost:3000' },
        { key: 'authToken', value: 'your-jwt-token-here' },
        { key: 'adminToken', value: 'your-admin-jwt-token-here' },
      ],
    };
  }
}
