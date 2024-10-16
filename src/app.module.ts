import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from './users/users.module';
import { User } from './users/entities/user.entity';
import { ConfigModule, ConfigService } from '@nestjs/config';

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
        return {
          type: configService.get<string>('DB_TYPE') as 'postgres',
          host: configService.get<string>('HOST'),
          port: configService.get<number>('PORT'),
          username: configService.get<string>('USER'),
          password: configService.get<string>('PASS'),
          database: configService.get<string>('DATABASE'),
          entities: [User],
          synchronize: true,
          ssl: configService.get<string>('SSL') === 'true',
        };
      },
    }),
    UsersModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
