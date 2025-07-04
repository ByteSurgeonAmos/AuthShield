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
export class AdminJwtAndApiKeyGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();

    // First, validate API key (ensures request comes from app gateway)
    if (!this.validateApiKey(request)) {
      throw new UnauthorizedException(
        'Valid API key required - requests must come through app gateway',
      );
    }

    // Then, validate JWT token and admin permissions
    if (!this.validateAdminJwtToken(request)) {
      throw new ForbiddenException('Admin JWT token required');
    }

    return true;
  }

  private validateApiKey(request: any): boolean {
    const apiKey = this.extractApiKey(request);

    if (!apiKey) {
      return false;
    }

    const validApiKey = this.configService.get<string>('API_KEY');

    if (!validApiKey || apiKey !== validApiKey) {
      return false;
    }

    request.isApiKeyAuth = true;
    return true;
  }

  private validateAdminJwtToken(request: any): boolean {
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
      return true;
    } catch {
      return false;
    }
  }

  private extractApiKey(request: any): string | null {
    const apiKeyHeader = request.headers['x-api-key'];
    const authHeader = request.headers['authorization'];

    if (apiKeyHeader) {
      return apiKeyHeader;
    }

    // Check if there's a separate API key in a custom header
    const gatewayApiKey = request.headers['x-gateway-api-key'];
    if (gatewayApiKey) {
      return gatewayApiKey;
    }

    return null;
  }
}
