import { Module } from '@nestjs/common';
import { ApiDocsController } from './api-docs.controller';

@Module({
  controllers: [ApiDocsController],
})
export class ApiDocsModule {}
