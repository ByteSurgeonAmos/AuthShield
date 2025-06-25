import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class UserProfileDto {
  @ApiProperty({
    description: 'User ID',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  userId: string;

  @ApiProperty({
    description: 'Username',
    example: 'johndoe',
  })
  username: string;

  @ApiProperty({
    description: 'Email address',
    example: 'john.doe@example.com',
  })
  email: string;

  @ApiPropertyOptional({
    description: 'Full name',
    example: 'John Doe',
  })
  fullname?: string;

  @ApiPropertyOptional({
    description: 'Phone number',
    example: '+1234567890',
  })
  phoneNumber?: string;

  @ApiPropertyOptional({
    description: 'Country',
    example: 'United States',
  })
  country?: string;

  @ApiPropertyOptional({
    description: 'User biography',
    example: 'Software developer passionate about technology',
  })
  userBio?: string;

  @ApiProperty({
    description: 'Account activation status',
    example: true,
  })
  isAccountActive: boolean;

  @ApiProperty({
    description: 'Email verification status',
    example: true,
  })
  emailVerified: boolean;

  @ApiProperty({
    description: 'Two-factor authentication status',
    example: false,
  })
  is2FaEnabled: boolean;

  @ApiProperty({
    description: 'Registration date',
    example: '2024-01-15T10:30:00Z',
  })
  dateRegistrated: string;

  @ApiProperty({
    description: 'User roles',
    example: ['user'],
    type: [String],
  })
  roles: string[];
}

export class AnalyticsResponseDto {
  @ApiProperty({
    description: 'User summary statistics',
    example: {
      totalUsers: 1500,
      activeUsers: 1350,
      newUsersToday: 25,
      newUsersThisWeek: 150,
      newUsersThisMonth: 400,
    },
  })
  summary: object;

  @ApiProperty({
    description: 'Authentication provider statistics',
    example: [
      { provider: 'local', count: 1200 },
      { provider: 'google', count: 250 },
      { provider: 'facebook', count: 50 },
    ],
  })
  authProviders: object[];

  @ApiProperty({
    description: 'User distribution by country',
    example: [
      { country: 'United States', count: 500 },
      { country: 'Canada', count: 200 },
      { country: 'United Kingdom', count: 150 },
    ],
  })
  usersByCountry: object[];
}

export class SecurityAnalyticsDto {
  @ApiProperty({
    description: 'Two-factor authentication statistics',
    example: [
      { method: 'email', count: 300 },
      { method: 'phone', count: 150 },
      { method: 'authenticator', count: 100 },
    ],
  })
  twoFAStats: object[];

  @ApiProperty({
    description: 'Number of unverified users',
    example: 45,
  })
  unverifiedUsers: number;

  @ApiProperty({
    description: 'Number of inactive users',
    example: 120,
  })
  inactiveUsers: number;

  @ApiProperty({
    description: 'Overall security score (0-100)',
    example: 85,
  })
  securityScore: number;
}

export class BulkActionResponseDto {
  @ApiProperty({
    description: 'Results of bulk operation',
    example: [
      { userId: 'user1', status: 'activated' },
      { userId: 'user2', status: 'failed', error: 'User not found' },
    ],
  })
  results: object[];
}

export class NotificationDto {
  @ApiProperty({
    description: 'Notification ID',
    example: 'notif_123456',
  })
  id: string;

  @ApiProperty({
    description: 'Notification title',
    example: 'Security Alert',
  })
  title: string;

  @ApiProperty({
    description: 'Notification message',
    example: 'Suspicious login attempt detected',
  })
  message: string;

  @ApiProperty({
    description: 'Notification type',
    example: 'security',
  })
  type: string;

  @ApiProperty({
    description: 'Priority level',
    example: 'high',
  })
  priority: string;

  @ApiProperty({
    description: 'Read status',
    example: false,
  })
  isRead: boolean;

  @ApiProperty({
    description: 'Creation timestamp',
    example: '2024-01-15T10:30:00Z',
  })
  createdAt: string;
}
