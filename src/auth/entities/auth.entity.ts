import {
  Entity,
  PrimaryColumn,
  Column,
  OneToMany,
  OneToOne,
  JoinColumn,
} from 'typeorm';
import { UserRole } from './user-role.entity';
import { UserDetails } from './user-details.entity';
import { SecurityQuestion } from './security-question.entity';

@Entity('user_account')
export class User {
  @PrimaryColumn({
    name: 'user_id',
    type: 'varchar',
    length: 255,
    nullable: false,
  })
  userId: string;

  @Column({ type: 'varchar', nullable: true })
  username: string;

  @Column({ type: 'varchar', nullable: true, unique: true })
  email: string;

  @Column({ name: 'email_verified', type: 'boolean', default: false })
  emailVerified: boolean;

  @Column({ name: 'phoneNo_verified', type: 'boolean', default: false })
  phoneNoVerified: boolean;

  @Column({ name: 'OtpCode', type: 'varchar', nullable: true })
  otpCode: string;

  @Column({ name: 'otpExip', type: 'varchar', nullable: true })
  otpExpiry: string;

  @Column({ name: 'isVerified', type: 'boolean', default: false })
  isVerified: boolean;

  @Column({ name: 'isAccountActive', type: 'boolean', default: true })
  isAccountActive: boolean;

  @Column({ name: 'is2FaEnabled', type: 'boolean', default: false })
  is2FaEnabled: boolean;

  @Column({ name: 'dateregistered', type: 'varchar', nullable: true })
  dateRegistrated: string;

  @Column({ type: 'varchar', nullable: true, default: 'NOPASS' })
  password: string;

  @Column({
    name: 'auth_provider',
    type: 'varchar',
    length: 50,
    nullable: true,
  })
  authProvider: string;

  @Column({ type: 'varchar', nullable: true })
  phone: string;

  @Column({
    name: 'two_factor_secret',
    type: 'varchar',
    length: 200,
    nullable: true,
  })
  twoFactorSecret: string;

  @Column({
    name: 'two_factor_method',
    type: 'varchar',
    length: 20,
    nullable: true,
  })
  twoFactorMethod: string;
  @Column({
    name: 'two_factor_backup_codes',
    type: 'text',
    nullable: true,
  })
  twoFactorBackupCodes: string;

  @Column({ name: 'login_notification_email', type: 'boolean', default: true })
  loginNotificationEmail: boolean;

  @Column({ name: 'phone_number', type: 'varchar', nullable: true })
  phoneNumber: string;

  @Column({
    name: 'completedtrades',
    type: 'integer',
    nullable: true,
    default: 0,
  })
  completedTrades: number;

  @Column({ name: 'country_code', type: 'varchar', length: 5, nullable: true })
  countryCode: string;

  @Column({ name: 'username_changed', type: 'boolean', default: false })
  usernameChanged: boolean;

  @Column({
    name: 'referal_by_account',
    type: 'varchar',
    length: 50,
    nullable: true,
  })
  referalByAccount: string;

  @Column({ name: 'last_login', type: 'timestamp', nullable: true })
  lastLogin: Date;

  @Column({ name: 'failed_login_attempts', type: 'integer', default: 0 })
  failedLoginAttempts: number;

  @Column({ name: 'account_locked_until', type: 'timestamp', nullable: true })
  accountLockedUntil: Date;

  @Column({ name: 'email_verification_token', type: 'varchar', nullable: true })
  emailVerificationToken: string;

  @Column({
    name: 'email_verification_expires',
    type: 'timestamp',
    nullable: true,
  })
  emailVerificationExpires: Date;

  @Column({ name: 'password_reset_token', type: 'varchar', nullable: true })
  passwordResetToken: string;

  @Column({ name: 'password_reset_expires', type: 'timestamp', nullable: true })
  passwordResetExpires: Date;
  @OneToMany(() => UserRole, (userRole) => userRole.user, { eager: true })
  roles: UserRole[];
  @OneToOne(() => UserDetails, (userDetails) => userDetails.user, {
    eager: true,
  })
  @JoinColumn({ name: 'userId', referencedColumnName: 'userId' })
  details: UserDetails;

  @OneToMany(
    () => SecurityQuestion,
    (securityQuestion) => securityQuestion.user,
  )
  securityQuestions: SecurityQuestion[];

  @Column({ name: 'phone_verification_token', type: 'varchar', nullable: true })
  phoneVerificationToken: string;

  @Column({
    name: 'phone_verification_expires',
    type: 'timestamp',
    nullable: true,
  })
  phoneVerificationExpires: Date;
}
