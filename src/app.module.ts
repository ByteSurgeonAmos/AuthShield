import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from './users/users.module';
import { User } from './users/entities/user.entity';
import { UsersController } from './users/users.controller';
import { UsersService } from './users/users.service';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      host: 'ep-wispy-mouse-a5t4bnt4.us-east-2.aws.neon.tech',
      type: 'postgres',
      port: 5432,
      password: 'wNC3Lz6Bofgi',
      database: 'test',
      username: 'x-mobit-base_owner',
      entities: [User],
      synchronize: true,
      ssl: true,
    }),
    UsersModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
