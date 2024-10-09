import { Entity, PrimaryGeneratedColumn, Column } from 'typeorm';
@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column({ unique: true })
  username: string;

  @Column()
  password: string;

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

  @Column({ default: () => '' })
  lastFailedLogin: Date;

  @Column({ default: () => '' })
  passwordResetToken: Date;

  @Column({ default: false })
  passwordResetTokenExpired: boolean;

  @Column({ default: false })
  isAdmin: boolean;

  @Column({ default: false })
  isEmailVerified: boolean;
}
