import { IsOptional, IsDateString, IsEnum } from 'class-validator';

export enum AnalyticsTimeframe {
  DAILY = 'daily',
  WEEKLY = 'weekly',
  MONTHLY = 'monthly',
  YEARLY = 'yearly',
}

export class AnalyticsQueryDto {
  @IsOptional()
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;

  @IsOptional()
  @IsEnum(AnalyticsTimeframe)
  timeframe?: AnalyticsTimeframe;
}
