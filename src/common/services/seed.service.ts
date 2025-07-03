import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../auth/entities/auth.entity';
import { UserRole, UserRoleType } from '../../auth/entities/user-role.entity';
import { UserDetails } from '../../auth/entities/user-details.entity';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { UsersService } from '../../auth/auth.service';
import { TwoFactorMethod } from '../../auth/dto/setup-2fa.dto';

@Injectable()
export class SeedService {
  private readonly logger = new Logger(SeedService.name);

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
    @InjectRepository(UserRole)
    private readonly roleRepository: Repository<UserRole>,
    @InjectRepository(UserDetails)
    private readonly detailsRepository: Repository<UserDetails>,
    private readonly configService: ConfigService,
    private readonly usersService: UsersService,
  ) {}

  async seedAdminUser(): Promise<void> {
    try {
      const adminExists = await this.userRepository
        .createQueryBuilder('user')
        .innerJoin('user.roles', 'role')
        .where('role.roles = :superRole', {
          superRole: UserRoleType.SUPER_ADMIN,
        })
        .getOne();

      if (adminExists) {
        this.logger.log('✅ Admin user already exists, skipping creation');
        this.logger.log(`📧 Existing admin email: ${adminExists.email}`);
        return;
      }

      this.logger.log('🔧 Creating default admin user...');

      const adminPassword = this.configService.get<string>(
        'ADMIN_DEFAULT_PASSWORD',
      );
      if (!adminPassword) {
        this.logger.error(
          '❌ ADMIN_DEFAULT_PASSWORD not found in environment variables',
        );
        this.logger.error(
          '💡 Please add ADMIN_DEFAULT_PASSWORD=your_password to your .env file',
        );
        return;
      }

      if (adminPassword.length < 8) {
        this.logger.error(
          '❌ ADMIN_DEFAULT_PASSWORD must be at least 8 characters long',
        );
        return;
      }

      const adminEmail = 'admin@xmobit.com';
      const adminUserId = uuidv4();

      const hashedPassword = await bcrypt.hash(adminPassword, 12);

      const adminUser = this.userRepository.create({
        userId: adminUserId,
        username: 'admin_xmobit',
        email: adminEmail,
        password: hashedPassword,
        emailVerified: true,
        isVerified: true,
        isAccountActive: true,
        authProvider: 'local',
        dateRegistrated: new Date().toISOString(),
        is2FaEnabled: true,
        twoFactorMethod: TwoFactorMethod.EMAIL, // Default 2FA method as email
        emailVerificationToken: null,
        emailVerificationExpires: null,
      });

      const savedUser = await this.userRepository.save(adminUser);
      this.logger.log(`✅ Admin user created with ID: ${savedUser.userId}`);

      const adminRole = this.roleRepository.create({
        userId: savedUser.userId,
        roles: UserRoleType.SUPER_ADMIN,
      });
      await this.roleRepository.save(adminRole);
      this.logger.log('✅ SUPER_ADMIN role assigned');

      const userDetails = this.detailsRepository.create({
        userId: savedUser.userId,
        fullname: 'Admin XMobit',
        country: 'System',
      });
      await this.detailsRepository.save(userDetails);
      this.logger.log('✅ Admin user details created');

      try {
        this.logger.log('🏦 Initiating wallet creation for admin user...');
        const walletResults = await this.usersService.triggerWalletCreation(
          adminEmail,
          adminUserId,
        );

        const successfulWallets = walletResults.filter(
          (result) => result.success,
        );
        const failedWallets = walletResults.filter((result) => !result.success);

        this.logger.log(
          `✅ Wallet creation completed: ${successfulWallets.length} successful, ${failedWallets.length} failed`,
        );

        if (failedWallets.length > 0) {
          this.logger.warn(
            '⚠️ Some wallets failed to create:',
            failedWallets.map((w) => w.name).join(', '),
          );
        }
      } catch (walletError) {
        throw new Error(
          `Wallet creation failed for admin user: ${walletError.message}`,
        );
      }
    } catch (error) {
      this.logger.error('❌ Failed to create admin user:', error);
      throw error;
    }
  }

  async checkAdminExists(): Promise<boolean> {
    try {
      const adminExists = await this.userRepository
        .createQueryBuilder('user')
        .innerJoin('user.roles', 'role')
        .where('role.roles = :superRole', {
          superRole: UserRoleType.SUPER_ADMIN,
        })
        .getOne();

      return !!adminExists;
    } catch (error) {
      this.logger.error('❌ Failed to check admin existence:', error);
      return false;
    }
  }
}
