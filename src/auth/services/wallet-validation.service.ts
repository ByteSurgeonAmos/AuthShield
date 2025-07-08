import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../entities/auth.entity';
import { UsersService } from '../auth.service';

@Injectable()
export class WalletValidationService {
  private readonly logger = new Logger(WalletValidationService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    private readonly usersService: UsersService,
  ) {}

  /**
   * Cron job that runs every 5 minutes for testing
   * For production: 0 2 * * * (Every day at 2:00 AM)
   * Current: every 2 AM
   */
  @Cron('0 2 * * *', {
    name: 'wallet-validation-check',
    timeZone: 'Africa/Nairobi',
  })
  async validateAllUserWallets(): Promise<void> {
    this.logger.log('🔍 Starting wallet validation cron job...');

    try {
      const users = await this.userRepository.find({
        select: ['userId', 'email', 'emailVerified', 'isAccountActive'],
        where: {
          emailVerified: true,
          isAccountActive: true,
        },
      });

      this.logger.log(
        `📊 Found ${users.length} verified and active users to check`,
      );

      let processedCount = 0;
      let walletsProcessed = 0;
      const batchSize = 10;

      for (let i = 0; i < users.length; i += batchSize) {
        const batch = users.slice(i, i + batchSize);

        const batchPromises = batch.map(async (user) => {
          try {
            this.logger.log(
              `🔨 Ensuring wallets exist for user ${user.userId}`,
            );

            const results = await this.usersService.triggerWalletCreation(
              user.email,
              user.userId,
            );

            const successfulCreations = results.filter((r) => r.success);
            const failedCreations = results.filter((r) => !r.success);

            if (successfulCreations.length > 0) {
              this.logger.log(
                `✅ Wallet creation initiated for user ${user.userId}: ${successfulCreations.map((r) => r.name).join(', ')}`,
              );
            }

            if (failedCreations.length > 0) {
              this.logger.warn(
                `⚠️ Some wallet creations failed for user ${user.userId}: ${failedCreations.map((r) => `${r.name} (${r.error})`).join(', ')}`,
              );
            }

            return { userId: user.userId, success: true };
          } catch (error) {
            this.logger.error(
              `❌ Error processing user ${user.userId}: ${error.message}`,
            );
            return {
              userId: user.userId,
              success: false,
              error: error.message,
            };
          }
        });

        const batchResults = await Promise.allSettled(batchPromises);
        const batchSuccessCount = batchResults.filter(
          (r) => r.status === 'fulfilled',
        ).length;

        processedCount += batch.length;
        walletsProcessed += batchSuccessCount;

        this.logger.log(
          `📈 Processed ${processedCount}/${users.length} users (${walletsProcessed} successful)`,
        );

        if (i + batchSize < users.length) {
          await new Promise((resolve) => setTimeout(resolve, 2000));
        }
      }

      this.logger.log(
        `✅ Wallet validation completed. Processed: ${processedCount} users, ` +
          `Successful wallet operations: ${walletsProcessed}`,
      );
    } catch (error) {
      this.logger.error(
        `💥 Wallet validation cron job failed: ${error.message}`,
      );
    }
  }

  async manualWalletValidation(userId?: string): Promise<any> {
    this.logger.log('🔧 Manual wallet validation triggered');

    if (userId) {
      const user = await this.userRepository.findOne({
        where: { userId },
        select: ['userId', 'email', 'emailVerified', 'isAccountActive'],
      });

      if (!user) {
        throw new Error(`User ${userId} not found`);
      }

      if (!user.emailVerified) {
        throw new Error(`User ${userId} email not verified`);
      }

      if (!user.isAccountActive) {
        throw new Error(`User ${userId} account not active`);
      }

      this.logger.log(`🔨 Ensuring wallets exist for user ${user.userId}`);

      const results = await this.usersService.triggerWalletCreation(
        user.email,
        user.userId,
      );

      const successfulCreations = results.filter((r) => r.success);
      const failedCreations = results.filter((r) => !r.success);

      return {
        userId: user.userId,
        results,
        successful: successfulCreations.map((r) => r.name),
        failed: failedCreations.map((r) => ({ name: r.name, error: r.error })),
        action: 'wallet_creation_initiated',
      };
    } else {
      // Run for all users
      await this.validateAllUserWallets();
      return {
        message: 'Full validation completed for all verified and active users',
      };
    }
  }

  getCronJobInfo(): any {
    return {
      name: 'wallet-validation-check',
      schedule: '0 2 * * *', // Daily at 2 AM UTC
      description:
        'Ensures all verified and active users have BTC and XMR spot and funding wallets',
      timezone: 'UTC',
      nextExecution: 'Daily at 2:00 AM UTC',
      status: 'active',
    };
  }
}
