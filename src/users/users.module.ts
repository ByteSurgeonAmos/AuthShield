import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),

    UsersModule,
    PassportModule,
    JwtModule.register({
      secret: 'topsecret11063',
      signOptions: { expiresIn: '1h' },
    }),
  ],

  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
