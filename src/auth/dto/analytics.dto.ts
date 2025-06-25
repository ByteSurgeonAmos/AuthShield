import { IsOptional, IsDateString, IsEnum } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export enum AnalyticsTimeframe {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
  YEARLY = 'yearly',
}

export class AnalyticsQueryDto {
  @ApiPropertyOptional({
    description: 'Start date for analytics query (ISO 8601 format)',
    example: '2024-01-01T00:00:00.000Z',
    format: 'date',
  })
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @ApiPropertyOptional({
    description: 'End date for analytics query (ISO 8601 format)',
    example: '2024-12-31T23:59:59.999Z',
    format: 'date',
  })
  @IsOptional()
  @IsDateString()
  endDate?: string;

  @ApiPropertyOptional({
    description: 'Timeframe for analytics aggregation',
    enum: AnalyticsTimeframe,
    example: AnalyticsTimeframe.MONTHLY,
  })
  @IsOptional()
  @IsEnum(AnalyticsTimeframe)
  timeframe?: AnalyticsTimeframe;
}
