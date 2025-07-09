import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(private configService: ConfigService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const apiKey = this.extractApiKey(request);

    if (!apiKey) {
      throw new UnauthorizedException('API key is missing');
    }

    const validApiKey = this.configService.get<string>('API_KEY');

    if (!validApiKey) {
      throw new UnauthorizedException('API key authentication not configured');
    }

    if (apiKey !== validApiKey) {
      throw new UnauthorizedException('Invalid API key');
    }

    request.isApiKeyAuth = true;
    return true;
  }

  private extractApiKey(request: any): string | null {
    const apiKeyHeader = request.headers['x-api-key'];
    const authHeader = request.headers['authorization'];

    if (apiKeyHeader) {
      return apiKeyHeader;
    }

    if (authHeader && authHeader.startsWith('ApiKey ')) {
      return authHeader.substring(7);
    }

    return null;
  }
}
