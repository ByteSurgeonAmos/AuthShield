import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from './auth.entity';

@Entity('security_questions')
export class SecurityQuestion {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  @Column({ name: 'user_id', type: 'varchar', length: 255 })
  userId: string;

  @Column({ type: 'varchar', nullable: true, length: 500 })
  question: string;

  @Column({ name: 'answer', nullable: true, type: 'varchar', length: 255 })
  answerHash: string;

  @Column({ name: 'is_changed', type: 'boolean', default: false })
  isChanged: boolean;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id', referencedColumnName: 'userId' })
  user: User;
}
