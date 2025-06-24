import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Logger, ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    credentials: true,
  });

  app.setGlobalPrefix('api/v1');

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const config = new DocumentBuilder()
    .setTitle('Auth Engine  API')
    .setDescription(
      'Comprehensive user management microservice for Xmobit platform with advanced authentication, 2FA, security auditing, and analytics',
    )
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
      },
      'access-token',
    )
    .addTag('Authentication', 'User authentication and login endpoints')
    .addTag('User Management', 'User CRUD operations and profile management')
    .addTag('2FA', 'Two-factor authentication setup and verification')
    .addTag(
      'Security',
      'Security audit logs and suspicious activity monitoring',
    )
    .addTag('Analytics', 'User analytics and dashboard statistics')
    .addTag('Admin', 'Administrative operations and bulk actions')
    .addTag('Notifications', 'User notification management')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
    },
  });

  const port = process.env.PORT || 3000;
  await app.listen(port);
  Logger.log(
    ` Auth Engine Service is running on: http://localhost:${port}/api/v1`,
    'INFO',
  );
  Logger.log(`Swagger API Documentation: http://localhost:${port}/api`, 'INFO');
}

bootstrap();
