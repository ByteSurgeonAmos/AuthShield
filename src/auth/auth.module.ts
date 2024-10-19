import { Module } from '@nestjs/common';
import { UsersService } from './auth.service';
import { UsersController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Auth } from './entities/auth.entity';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { SmsModule } from 'src/sms/sms.module';

@Module({
  imports: [
    TypeOrmModule.forFeature([Auth]),

    UsersModule,
    PassportModule,
    JwtModule.register({
      secret: 'topsecret11063',
      signOptions: { expiresIn: '1h' },
    }),
    SmsModule,
  ],

  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
