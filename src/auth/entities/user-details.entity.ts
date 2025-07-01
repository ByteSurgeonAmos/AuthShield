import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToOne,
  JoinColumn,
} from 'typeorm';
import { User } from './auth.entity';

@Entity('other_user_details')
export class UserDetails {
  @PrimaryGeneratedColumn()
  id: number;
  @Column({ name: 'user_id', type: 'varchar', length: 255 })
  userId: string;

  @Column({ type: 'varchar', nullable: true })
  fullname: string;

  @Column({ name: 'profile_pic_url', type: 'varchar', nullable: true })
  profilePicUrl: string;

  @Column({ name: 'user_bio', type: 'varchar', nullable: true })
  userBio: string;

  @Column({ type: 'varchar', nullable: true })
  country: string;
  @OneToOne(() => User, (user) => user.details)
  @JoinColumn({ name: 'user_id', referencedColumnName: 'userId' })
  user: User;

  @Column({ name: 'payment_details', type: 'text', nullable: true })
  paymentDetails: string;

  @Column({ name: 'third_party_provider', type: 'varchar', nullable: true })
  thirdPartyProvider: string;
}
