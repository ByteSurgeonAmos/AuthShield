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
    this.logger.log(
      `📥 ${method} ${originalUrl} | IP: ${ip} | ID: ${requestId}`,
    );

    return next.handle().pipe(
      tap({
        next: (responseData) => {
          const duration = Date.now() - startTime;
          const { statusCode } = response;

          // Log successful response
          this.logger.log(
            `📤 ${statusCode} ${method} ${originalUrl} | ${duration}ms | ID: ${requestId}`,
          );
        },
        error: (error) => {
          const duration = Date.now() - startTime;
          const statusCode = error.status || error.statusCode || 500;

          // Log error response
          this.logger.error(
            `❌ ${statusCode} ${method} ${originalUrl} | ${duration}ms | ${error.message} | ID: ${requestId}`,
          );
        },
      }),
    );
  }
}
