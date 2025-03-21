import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
} from 'typeorm';

@Entity('like')
export class Like {
  @PrimaryGeneratedColumn({ name: 'id' })
  id: number;

  @Column({ name: 'user_uuid', type: 'uuid' })
  userUuid: string;

  @Column({ name: 'user_id', type: 'int' })
  userId: number;

  @Column({ name: 'post_id', type: 'int' })
  postId: number;

  @CreateDateColumn({ name: 'created_at', type: 'timestamptz' })
  createdAt: Date;
}
