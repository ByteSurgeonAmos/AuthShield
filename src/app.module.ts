import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from './auth/auth.module';
import { User } from './auth/entities/auth.entity';
import { UserRole } from './auth/entities/user-role.entity';
import { UserDetails } from './auth/entities/user-details.entity';
import { SecurityAuditLog } from './auth/entities/security-audit-log.entity';
import { AuthNotification } from './auth/entities/auth-notification.entity';
import { SecurityQuestion } from './auth/entities/security-question.entity';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { SmsModule } from './sms/sms.module';
import { HealthModule } from './health/health.module';
import { ApiDocsModule } from './api-docs/api-docs.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      envFilePath: '.env',
      isGlobal: true,
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const databaseUrl = configService.get<string>('DATABASE_URL');
        if (databaseUrl) {
          const url = new URL(databaseUrl);
          return {
            type: 'postgres',
            host: url.hostname,
            port: parseInt(url.port) || 5432,
            username: url.username,
            password: url.password,
            database: url.pathname.slice(1),
            entities: [
              User,
              UserRole,
              UserDetails,
              SecurityAuditLog,
              AuthNotification,
              SecurityQuestion,
            ],
            synchronize:
              process.env.NODE_ENV === 'development' &&
              process.env.FORCE_SYNC === 'true',
            ssl: configService.get<string>('SSL') === 'true',
            logging: process.env.NODE_ENV === 'development',
          };
        }
        return {
          type: 'postgres',
          host: configService.get<string>('HOST') || 'localhost',
          port: configService.get<number>('PORT') || 5432,
          username:
            configService.get<string>('USER') ||
            configService.get<string>('USERNAME'),
          password:
            configService.get<string>('PASS') ||
            configService.get<string>('PASSWORD'),
          database: configService.get<string>('DATABASE'),
          entities: [
            User,
            UserRole,
            UserDetails,
            SecurityAuditLog,
            AuthNotification,
            SecurityQuestion,
          ],
          synchronize:
            process.env.NODE_ENV === 'development' &&
            process.env.FORCE_SYNC === 'true',
          ssl: configService.get<string>('SSL') === 'true',
          logging: process.env.NODE_ENV === 'development',
        };
      },
    }),
    UsersModule,
    SmsModule,
    HealthModule,
    ApiDocsModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
