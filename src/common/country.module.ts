import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { HttpModule } from '@nestjs/axios';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { CountryUpdateService } from './services/country-update.service';
import { CountryController } from './controllers/country.controller';
import { User } from '../auth/entities/auth.entity';
import { UserDetails } from '../auth/entities/user-details.entity';
import { JwtStrategy } from '../auth/strategies/jwt.strategy';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, UserDetails]),
    HttpModule.register({
      timeout: 10000,
      maxRedirects: 5,
    }),
    PassportModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '24h' },
      }),
    }),
  ],
  providers: [CountryUpdateService, JwtStrategy],
  controllers: [CountryController],
  exports: [CountryUpdateService],
})
export class CountryModule {}
