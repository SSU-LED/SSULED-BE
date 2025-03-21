import { forwardRef, Module } from '@nestjs/common';
import { CommentsService } from './comments.service';
import { CommentsController } from './comments.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { PostsModule } from '@/modules/posts/posts.module';
import { Comment } from '@/entities/comment.entity';
import { User } from '@/entities/user.entity';
@Module({
  imports: [
    TypeOrmModule.forFeature([Comment, User]),
    forwardRef(() => PostsModule),
  ],
  controllers: [CommentsController],
  providers: [CommentsService],
  exports: [CommentsService],
})
export class CommentsModule {}
