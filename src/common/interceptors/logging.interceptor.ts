import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { Request, Response } from 'express';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(LoggingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const httpContext = context.switchToHttp();
    const request = httpContext.getRequest<Request>();
    const response = httpContext.getResponse<Response>();

    const { method, originalUrl, ip } = request;
    const userAgent = request.get('User-Agent') || 'unknown';
    const startTime = Date.now();

    // Generate unique request ID
    const requestId = Math.random().toString(36).substring(2, 15);

    // Log incoming request
    this.logger.log(`📥 Incoming ${method} ${originalUrl}`, {
      requestId,
      method,
      url: originalUrl,
      ip,
      userAgent,
      timestamp: new Date().toISOString(),
    });

    return next.handle().pipe(
      tap({
        next: (responseData) => {
          const duration = Date.now() - startTime;
          const { statusCode } = response;

          // Log successful response
          this.logger.log(
            `📤 Response ${statusCode} ${method} ${originalUrl}`,
            {
              requestId,
              method,
              url: originalUrl,
              statusCode,
              duration: `${duration}ms`,
              ip,
              userAgent,
              timestamp: new Date().toISOString(),
            },
          );
        },
        error: (error) => {
          const duration = Date.now() - startTime;
          const statusCode = error.status || error.statusCode || 500;

          // Log error response
          this.logger.error(`❌ Error ${statusCode} ${method} ${originalUrl}`, {
            requestId,
            method,
            url: originalUrl,
            statusCode,
            duration: `${duration}ms`,
            error: error.message,
            stack: error.stack,
            ip,
            userAgent,
            timestamp: new Date().toISOString(),
          });
        },
      }),
    );
  }
}
