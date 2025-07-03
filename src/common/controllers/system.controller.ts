import { Controller, Get } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { SeedService } from '../services/seed.service';

@ApiTags('System')
@Controller('system')
export class SystemController {
  constructor(private readonly seedService: SeedService) {}

  @Get('admin-status')
  @ApiOperation({
    summary: 'Check admin user status',
    description: 'Check if admin user exists in the system',
  })
  @ApiResponse({
    status: 200,
    description: 'Admin status information',
    schema: {
      type: 'object',
      properties: {
        adminExists: { type: 'boolean' },
        message: { type: 'string' },
      },
    },
  })
  async checkAdminStatus() {
    const adminExists = await this.seedService.checkAdminExists();

    return {
      adminExists,
      message: adminExists
        ? 'Admin user exists in the system'
        : 'No admin user found in the system',
    };
  }

  @Get('seed-admin')
  @ApiOperation({
    summary: 'Manually trigger admin user creation',
    description: 'Manually create admin user if it does not exist',
  })
  @ApiResponse({
    status: 200,
    description: 'Admin seeding result',
  })
  async seedAdmin() {
    try {
      await this.seedService.seedAdminUser();
      return {
        success: true,
        message: 'Admin user seeding completed successfully',
      };
    } catch (error) {
      return {
        success: false,
        message: 'Admin user seeding failed',
        error: error.message,
      };
    }
  }
}
