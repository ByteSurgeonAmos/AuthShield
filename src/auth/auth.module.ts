import { Module } from '@nestjs/common';
import { UsersService } from './auth.service';
import { UsersController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/auth.entity';
import { UserRole } from './entities/user-role.entity';
import { UserDetails } from './entities/user-details.entity';
import { SecurityQuestion } from './entities/security-question.entity';
import { SecurityAuditLog } from './entities/security-audit-log.entity';
import { AuthNotification } from './entities/auth-notification.entity';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { SmsModule } from 'src/sms/sms.module';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { JwtAdminGuard } from './guards/jwt-admin.guard';
import { SecurityAuditService } from './services/security-audit.service';
import { NotificationService } from './services/notification.service';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      User,
      UserRole,
      UserDetails,
      SecurityQuestion,
      SecurityAuditLog,
      AuthNotification,
    ]),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '24h' },
      }),
    }),
    SmsModule,
    HttpModule
  ],
  controllers: [UsersController],
  providers: [
    UsersService,
    JwtAuthGuard,
    JwtAdminGuard,
    SecurityAuditService,
    NotificationService,
  ],
  exports: [
    UsersService,
    TypeOrmModule,
    JwtAuthGuard,
    JwtAdminGuard,
    SecurityAuditService,
    NotificationService,
  ],
})
export class UsersModule {}
