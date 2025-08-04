import { Controller, Post, Get, Query, UseGuards } from '@nestjs/common';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiQuery,
} from '@nestjs/swagger';
import { CountryUpdateService } from '../services/country-update.service';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';

@ApiTags('Country Management')
@Controller('countries')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class CountryController {
  constructor(private readonly countryUpdateService: CountryUpdateService) {}

  @Post('update-from-codes')
  @ApiOperation({
    summary: 'Manually trigger country update from country codes',
    description:
      'Updates user countries based on their country codes using REST Countries API',
  })
  @ApiQuery({
    name: 'forceUpdate',
    required: false,
    type: Boolean,
    description: 'Whether to update countries even if they already exist',
  })
  @ApiResponse({
    status: 200,
    description: 'Country update completed',
    schema: {
      type: 'object',
      properties: {
        updated: { type: 'number' },
        failed: { type: 'number' },
        skipped: { type: 'number' },
        details: { type: 'array', items: { type: 'string' } },
      },
    },
  })
  async manualUpdateCountries(@Query('forceUpdate') forceUpdate?: boolean) {
    return await this.countryUpdateService.manualUpdateAllCountries(
      forceUpdate === true,
    );
  }

  @Get('mapping-stats')
  @ApiOperation({
    summary: 'Get country mapping statistics',
    description:
      'Returns statistics about users with country codes and countries',
  })
  @ApiResponse({
    status: 200,
    description: 'Country mapping statistics',
    schema: {
      type: 'object',
      properties: {
        totalUsers: { type: 'number' },
        usersWithCountryCode: { type: 'number' },
        usersWithCountry: { type: 'number' },
        usersNeedingUpdate: { type: 'number' },
        countryCodeDistribution: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              countryCode: { type: 'string' },
              count: { type: 'number' },
            },
          },
        },
      },
    },
  })
  async getCountryMappingStats() {
    return await this.countryUpdateService.getCountryMappingStats();
  }
}
