import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class LoginResponseDto {
  @ApiProperty({
    description: 'Authentication token',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  accesstoken?: string;

  @ApiProperty({
    description: 'User information object',
    example: { id: 'user123', username: 'johndoe', email: 'john@example.com' },
  })
  user?: object;

  @ApiPropertyOptional({
    description: 'Whether two-factor authentication is required',
    example: true,
  })
  requiresTwoFactor?: boolean;

  @ApiPropertyOptional({
    description: 'Temporary token for 2FA verification',
    example: 'temp_token_abc123',
  })
  temporaryToken?: string;

  @ApiProperty({
    description: 'Response message',
    example: 'Login successful',
  })
  message: string;

  @ApiProperty({
    description: 'HTTP status code',
    example: 200,
  })
  statusCode: number;
}

export class RegisterResponseDto {
  @ApiProperty({
    description: 'Created user ID',
    example: 'a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6',
  })
  userId: string;

  @ApiProperty({
    description: 'Email address',
    example: 'john.doe@example.com',
  })
  email: string;

  @ApiProperty({
    description: 'Full name',
    example: 'John Doe',
  })
  fullname: string;

  @ApiPropertyOptional({
    description: 'Temporary username (can be changed later)',
    example: 'user_abc123',
  })
  tempUsername?: string;

  @ApiProperty({
    description: 'Response message',
    example:
      'Account created successfully. Please check your email for verification.',
  })
  message: string;

  @ApiProperty({
    description: 'Whether profile setup is complete',
    example: false,
  })
  profileComplete: boolean;
}

export class ProfileCompleteResponseDto {
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
    description: 'Profile image URL',
    example: 'https://example.com/profile.jpg',
  })
  profileImage?: string;

  @ApiProperty({
    description: 'Response message',
    example: 'Profile completed successfully',
  })
  message: string;

  @ApiProperty({
    description: 'Whether profile setup is complete',
    example: true,
  })
  profileComplete: boolean;
}

export class Setup2FAResponseDto {
  @ApiProperty({
    description: 'Setup status message',
    example: '2FA setup initiated successfully',
  })
  message: string;

  @ApiPropertyOptional({
    description: 'Secret key for authenticator apps',
    example: 'JBSWY3DPEHPK3PXP',
  })
  secret?: string;

  @ApiPropertyOptional({
    description: 'QR code URL for authenticator apps',
    example: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...',
  })
  qrCodeUrl?: string;
}

export class MessageResponseDto {
  @ApiProperty({
    description: 'Response message',
    example: 'Operation completed successfully',
  })
  message: string;
}

export class BooleanResponseDto {
  @ApiProperty({
    description: 'Operation result',
    example: true,
  })
  valid: boolean;

  @ApiProperty({
    description: 'Response message',
    example: 'Verification successful',
  })
  message: string;
}
