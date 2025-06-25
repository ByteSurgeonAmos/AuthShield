import { SwaggerModule } from '@nestjs/swagger';

export const swaggerExamples = {
  // Authentication Examples
  registerExample: {
    summary: 'Register new user example',
    value: {
      email: 'john.doe@example.com',
      password: 'securePassword123',
      username: 'johndoe',
      phoneNumber: '+1234567890',
      fullname: 'John Doe',
      country: 'United States',
      countryCode: 'US',
      userBio: 'Software developer passionate about technology',
    },
  },

  loginExample: {
    summary: 'Login user example',
    value: {
      email: 'john.doe@example.com',
      password: 'securePassword123',
    },
  },

  setup2FAExample: {
    summary: 'Setup 2FA example',
    value: {
      method: 'email',
    },
  },

  verify2FAExample: {
    summary: 'Verify 2FA example',
    value: {
      token: '123456',
      userId: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
    },
  },

  // Update User Examples
  updateUserExample: {
    summary: 'Update user profile example',
    value: {
      fullname: 'John Smith',
      country: 'Canada',
      userBio: 'Senior software engineer with 10+ years experience',
      phoneNumber: '+1987654321',
    },
  },

  // Security Question Examples
  setSecurityQuestionExample: {
    summary: 'Set security question example',
    value: {
      question: 'What was the name of your first pet?',
      answer: 'Fluffy',
    },
  },

  verifySecurityQuestionExample: {
    summary: 'Verify security question example',
    value: {
      answer: 'Fluffy',
    },
  },

  // Admin Examples
  bulkUserIdsExample: {
    summary: 'Bulk operation example',
    value: {
      userIds: [
        'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
        'b2c3d4e5-f6g7-8h9i-0j1k-l2m3n4o5p6q7',
        'c3d4e5f6-g7h8-9i0j-1k2l-m3n4o5p6q7r8',
      ],
    },
  },

  assignRoleExample: {
    summary: 'Assign role example',
    value: {
      role: 'admin',
    },
  },

  // Notification Examples
  broadcastNotificationExample: {
    summary: 'Broadcast notification example',
    value: {
      title: 'System Maintenance',
      message: 'The system will be under maintenance from 2 AM to 4 AM EST.',
      type: 'system',
      priority: 'medium',
      userIds: [
        'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
        'b2c3d4e5-f6g7-8h9i-0j1k-l2m3n4o5p6q7',
      ],
    },
  },

  // Response Examples
  loginSuccessResponse: {
    summary: 'Successful login response',
    value: {
      accesstoken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
      user: {
        userId: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
        username: 'johndoe',
        email: 'john.doe@example.com',
        roles: ['user'],
      },
      message: 'Login successful',
      statusCode: 200,
    },
  },

  login2FARequiredResponse: {
    summary: 'Login requiring 2FA response',
    value: {
      requiresTwoFactor: true,
      temporaryToken: 'temp_token_abc123',
      message: 'Two-factor authentication required',
      statusCode: 200,
    },
  },

  registerSuccessResponse: {
    summary: 'Successful registration response',
    value: {
      userId: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
      username: 'johndoe',
      email: 'john.doe@example.com',
      message:
        'User registered successfully. Please check your email for verification.',
    },
  },

  userProfileResponse: {
    summary: 'User profile response',
    value: {
      userId: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
      username: 'johndoe',
      email: 'john.doe@example.com',
      fullname: 'John Doe',
      phoneNumber: '+1234567890',
      country: 'United States',
      userBio: 'Software developer passionate about technology',
      isAccountActive: true,
      emailVerified: true,
      is2FaEnabled: false,
      dateRegistrated: '2024-01-15T10:30:00Z',
      roles: ['user'],
    },
  },

  analyticsResponse: {
    summary: 'Analytics overview response',
    value: {
      summary: {
        totalUsers: 1500,
        activeUsers: 1350,
        newUsersToday: 25,
        newUsersThisWeek: 150,
        newUsersThisMonth: 400,
      },
      authProviders: [
        { provider: 'local', count: 1200 },
        { provider: 'google', count: 250 },
        { provider: 'facebook', count: 50 },
      ],
      usersByCountry: [
        { country: 'United States', count: 500 },
        { country: 'Canada', count: 200 },
        { country: 'United Kingdom', count: 150 },
      ],
    },
  },
};

export const swaggerTestingGuide = {
  title: 'API Testing Guide',
  description: `
    ## Getting Started with API Testing

    ### 1. Authentication Flow
    1. **Register**: POST /api/v1/users/register
    2. **Verify Email**: Check email and visit verification link
    3. **Login**: POST /api/v1/users/login
    4. **Copy JWT Token**: Use the returned token for authenticated requests

    ### 2. Using Bearer Authentication
    - Click "Authorize" button in Swagger UI
    - Enter: Bearer <your-jwt-token>
    - All protected endpoints will now include this token

    ### 3. Testing 2FA Setup
    1. **Setup 2FA**: POST /api/v1/users/setup-2fa
    2. **Verify Setup**: POST /api/v1/users/verify-2fa-setup
    3. **Test Login with 2FA**: Subsequent logins will require 2FA

    ### 4. Admin Endpoints
    - Requires admin role
    - Use admin JWT token for authentication
    - Test with user management and analytics endpoints

    ### 5. Common Test Scenarios

    #### User Registration and Verification
    \`\`\`
    POST /api/v1/users/register
    → Check email for verification link
    → POST /api/v1/users/verify-email?token=<token>
    \`\`\`

    #### Login with 2FA
    \`\`\`
    POST /api/v1/users/login
    → If 2FA enabled, use temporaryToken
    → POST /api/v1/users/verify-2fa-login
    \`\`\`

    #### Profile Management
    \`\`\`
    GET /api/v1/users/profile
    PATCH /api/v1/users/profile
    \`\`\`

    ### 6. Error Handling
    - 400: Bad Request - Check your input data
    - 401: Unauthorized - Check your JWT token
    - 403: Forbidden - Check user permissions
    - 404: Not Found - Resource doesn't exist
    - 429: Rate Limited - Too many requests
  `,
};

export const swaggerTags = [
  {
    name: 'Authentication',
    description: 'User registration, login, and email verification endpoints',
  },
  {
    name: '2FA',
    description: 'Two-factor authentication setup and verification',
  },
  {
    name: 'Phone Verification',
    description: 'Phone number verification with OTP',
  },
  {
    name: 'User Management',
    description: 'User profile and account management',
  },
  {
    name: 'Admin',
    description: 'Administrative operations and user management',
  },
  {
    name: 'Analytics',
    description: 'User analytics and dashboard statistics',
  },
  {
    name: 'Security',
    description: 'Security audit logs and monitoring',
  },
  {
    name: 'Notifications',
    description: 'User notification management',
  },
  {
    name: 'Security Questions',
    description: 'Security question management for account recovery',
  },
];
