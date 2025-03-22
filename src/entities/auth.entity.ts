import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('auth')
export class Auth {
  @PrimaryGeneratedColumn({ name: 'id' })
  id: number;

  @Column({ name: 'refresh_token', type: 'varchar', nullable: true })
  refreshToken: string;

  // @Column({ name: 'access_token', type: 'varchar', nullable: true })
  // accessToken: string;

  @Column({ name: 'user_id', type: 'int' })
  userId: number;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at', type: 'timestamptz' })
  updatedAt: Date;
}
