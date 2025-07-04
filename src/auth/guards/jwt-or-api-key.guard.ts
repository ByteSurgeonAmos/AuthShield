import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtOrApiKeyGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();

    // Try API key authentication first
    if (this.tryApiKeyAuth(request)) {
      return true;
    }

    // Fall back to JWT authentication
    if (this.tryJwtAuth(request)) {
      return true;
    }

    throw new UnauthorizedException(
      'Valid authentication required (JWT token or API key)',
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

      // Set flags to identify this as an API key authenticated request
      request.isApiKeyAuth = true;
      request.authMethod = 'api-key';
      return true;
    } catch {
      return false;
    }
  }

  private tryJwtAuth(request: any): boolean {
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

      request.user = payload;
      request.authMethod = 'jwt';
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
