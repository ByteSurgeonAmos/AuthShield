import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from './auth.entity';

export enum UserRoleType {
  USER = 'user',
  SYSTEM = 'system',
  SUPER_ADMIN = 'super_admin',
}

@Entity('Roles')
export class UserRole {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ name: 'user_id', type: 'varchar' })
  userId: string;

  @Column({
    type: 'varchar',
    enum: UserRoleType,
    default: UserRoleType.USER,
  })
  roles: UserRoleType;

  // Relationship
  @ManyToOne(() => User, (user) => user.roles)
  @JoinColumn({ name: 'user_id' })
  user: User;
}
