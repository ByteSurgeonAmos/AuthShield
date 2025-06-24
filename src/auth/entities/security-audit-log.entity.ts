import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from './auth.entity';

@Entity('security_audit_log')
export class SecurityAuditLog {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Column({ name: 'event_type' })
  eventType: string;

  @Column({ nullable: true })
  reason?: string;

  @Column({ name: 'user_id', nullable: true })
  userId?: string;

  @Column({ nullable: true })
  email?: string;

  @Column({ name: 'ip_address', nullable: true })
  ipAddress?: string;

  @Column({ name: 'user_agent', nullable: true })
  userAgent?: string;

  @Column({ name: 'session_id', nullable: true })
  sessionId?: string;

  @Column({ type: 'jsonb', name: 'additional_data', nullable: true })
  additionalData?: any;

  @CreateDateColumn({ name: 'timestamp' })
  timestamp: Date;

  @ManyToOne(() => User, { nullable: true })
  @JoinColumn({ name: 'user_id' })
  user?: User;
}
