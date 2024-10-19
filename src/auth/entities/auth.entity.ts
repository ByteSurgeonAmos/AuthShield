import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';
@Entity()
export class Auth {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column({ unique: true })
  username: string;

  @Column()
  password: string;
  @Column()
  phoneNumber: string;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  createdAt: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  updatedAt: Date;

  @Column({ default: true })
  isActive: boolean;

  @Column({ default: 0 })
  loginAttempts: number;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  lastLogin: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  lastFailedLogin: Date;

  @Column({ default: () => 'CURRENT_TIMESTAMP' })
  phoneOtpExpiry: Date;

  @Column({ nullable: true })
  passwordResetToken: string;

  @Column({ nullable: true })
  phoneVerificationOTP: string;

  @Column({ nullable: true })
  verificationToken: string;

  @Column({ nullable: true })
  verificationTokenExpires: Date;

  @Column({ default: false })
  passwordResetTokenExpired: boolean;

  @Column({ default: false })
  isAdmin: boolean;

  @Column({ default: false })
  isEmailVerified: boolean;

  @Column({ default: false })
  isPhoneVerified: boolean;
}
