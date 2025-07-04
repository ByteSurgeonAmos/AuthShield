import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserRoleType } from '../entities/user-role.entity';

@Injectable()
export class AdminOrApiKeyGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();

    // Try API key authentication first (API key has admin access)
    if (this.tryApiKeyAuth(request)) {
      return true;
    }

    // Fall back to JWT admin authentication
    if (this.tryJwtAdminAuth(request)) {
      return true;
    }

    throw new UnauthorizedException(
      'Admin authentication required (JWT admin token or API key)',
    );
  }

  private tryApiKeyAuth(request: any): boolean {
    try {
      const apiKey = this.extractApiKey(request);

      if (!apiKey) {
        return false;
      }

      const validApiKey = this.configService.get<string>('API_KEY');

      if (!validApiKey || apiKey !== validApiKey) {
        return false;
      }

      // API key grants admin access
      request.isApiKeyAuth = true;
      request.authMethod = 'api-key';
      request.hasAdminAccess = true;
      return true;
    } catch {
      return false;
    }
  }

  private tryJwtAdminAuth(request: any): boolean {
    try {
      const authHeader = request.headers['authorization'];
      const token =
        authHeader &&
        authHeader.startsWith('Bearer ') &&
        authHeader.split(' ')[1];

      if (!token) {
        return false;
      }

      const payload = this.jwtService.verify(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });

      // Check if user has admin role
      const userRoles = payload.roles || [];
      const hasAdminRole =
        userRoles.includes(UserRoleType.SUPER_ADMIN) ||
        userRoles.includes(UserRoleType.SYSTEM);

      if (!hasAdminRole) {
        return false;
      }

      request.user = payload;
      request.authMethod = 'jwt';
      request.hasAdminAccess = true;
      return true;
    } catch {
      return false;
    }
  }

  private extractApiKey(request: any): string | null {
    // Check multiple headers for API key
    const apiKeyHeader = request.headers['x-api-key'];
    const authHeader = request.headers['authorization'];

    if (apiKeyHeader) {
      return apiKeyHeader;
    }

    // Check if Authorization header contains API key (format: "ApiKey your-api-key")
    if (authHeader && authHeader.startsWith('ApiKey ')) {
      return authHeader.substring(7);
    }

    return null;
  }
}
