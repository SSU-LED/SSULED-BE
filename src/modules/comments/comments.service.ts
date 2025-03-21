import {
  Injectable,
  NotFoundException,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, DeepPartial, In } from 'typeorm';
import { CreateCommentDto } from './dto/create-comment.dto';
import { UpdateCommentDto } from './dto/update-comment.dto';
import { PostsService } from '@/modules/posts/posts.service';
import { FindAllCommentsDto } from './dto/find-all-comments.dto';
import { Comment } from '@/entities/comment.entity';
import { User } from '@/entities/user.entity';

@Injectable()
export class CommentsService {
  constructor(
    @InjectRepository(Comment)
    private commentRepository: Repository<Comment>,
    @Inject(forwardRef(() => PostsService))
    private postsService: PostsService,
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  /**
   * 댓글 생성
   * @param createCommentDto 댓글 생성 정보
   * @returns 생성된 댓글 정보
   */
  async createComment(createCommentDto: CreateCommentDto) {
    // 게시글 존재 여부 확인
    await this.postsService.findOnePost(createCommentDto.postId);

    const userId = await this.getUserIdByUuid(createCommentDto.userUuid);

    const comment = this.commentRepository.create({
      ...createCommentDto,
      userId,
    } as DeepPartial<Comment>);

    await this.commentRepository.save(comment);

    const { id, content, userUuid, postId, createdAt, updatedAt } = comment;
    return { id, content, userUuid, postId, createdAt, updatedAt };
  }

  /**
   * 게시글의 모든 댓글 페이지별 조회
   * @param postId 게시글 ID
   * @param findAllCommentsDto 댓글 목록 조회 조건들
   * @returns 댓글 목록과 페이지네이션 메타데이터
   */
  async findAllComments(
    postId: number,
    findAllCommentsDto: FindAllCommentsDto,
  ) {
    const { page, limit } = findAllCommentsDto;

    // 게시글 존재 여부 확인
    await this.postsService.findOnePost(postId);

    const [comments, total] = await this.commentRepository.findAndCount({
      where: { postId },
      order: { createdAt: 'DESC' },
      skip: (page - 1) * limit,
      take: limit,
    });

    const userIds = [...new Set(comments.map((comment) => comment.userId))];
    const users = await this.userRepository.find({
      where: { id: In(userIds) },
      select: ['id', 'nickname', 'profileImage'],
    });

    const userMap = new Map(users.map((user) => [user.id, user]));

    const commentsWithUserInfo = comments.map((comment) => {
      const user = userMap.get(comment.userId);
      return {
        id: comment.id,
        content: comment.content,
        postId: comment.postId,
        createdAt: comment.createdAt,
        updatedAt: comment.updatedAt,
        user: user
          ? {
              userUuid: comment.userUuid,
              nickname: user.nickname,
              profileImage: user.profileImage,
            }
          : null,
      };
    });

    return {
      data: commentsWithUserInfo,
      meta: {
        totalItems: total,
        itemsPerPage: limit,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
      },
    };
  }

  /**
   * 게시글의 모든 댓글 목록 조회
   * @param postId 게시글 ID
   * @returns 댓글 목록
   */
  async getCommentsByPostId(postId: number) {
    const comments = await this.commentRepository.find({
      where: { postId },
      order: { createdAt: 'ASC' },
    });

    // 사용자 정보 조회
    const userIds = [...new Set(comments.map((comment) => comment.userId))];
    const users = await this.userRepository.find({
      where: { id: In(userIds) },
      select: ['id', 'userUuid', 'nickname', 'profileImage'],
    });

    const userMap = new Map(users.map((user) => [user.id, user]));

    return comments.map((comment) => {
      const user = userMap.get(comment.userId);
      return {
        id: comment.id,
        content: comment.content,
        userUuid: comment.userUuid,
        userName: user?.nickname || null,
        userProfileImage: user?.profileImage || null,
        createdAt: comment.createdAt,
        updatedAt: comment.updatedAt,
      };
    });
  }

  /**
   * 댓글 ID로 댓글 찾기
   * @param id 댓글 ID
   * @returns 댓글 정보
   */
  async findOneComment(id: number) {
    const comment = await this.commentRepository.findOne({ where: { id } });
    if (!comment) {
      throw new NotFoundException('해당 ID의 댓글을 찾을 수 없습니다.');
    }

    const {
      id: commentId,
      content,
      userUuid,
      postId,
      createdAt,
      updatedAt,
    } = comment;
    return { id: commentId, content, userUuid, postId, createdAt, updatedAt };
  }

  /**
   * 댓글 수정
   * @param id 댓글 ID
   * @param updateCommentDto 댓글 수정 정보
   * @returns 수정된 댓글 정보
   */
  async updateComment(id: number, updateCommentDto: UpdateCommentDto) {
    await this.findOneComment(id);

    // TODO: 댓글 작성자 체크 로직 추가

    await this.commentRepository.update(id, {
      ...updateCommentDto,
      updatedAt: new Date(),
    });

    return this.findOneComment(id);
  }

  /**
   * 댓글 삭제
   * @param id 댓글 ID
   * @returns 삭제 성공 메시지
   */
  async removeComment(id: number) {
    await this.findOneComment(id);

    // TODO: 댓글 작성자 체크 로직 추가

    await this.commentRepository.delete(id);

    return {
      message: '댓글이 성공적으로 삭제되었습니다.',
    };
  }

  /**
   * 게시글의 댓글 수 조회
   * @param postId 게시글 ID
   * @returns 댓글 수
   */
  async getCommentCountByPostId(postId: number): Promise<number> {
    return this.commentRepository.count({
      where: { postId },
    });
  }

  /**
   * 여러 게시글의 댓글 수 조회
   * @param postIds 게시글 ID 배열
   * @returns 게시글 ID를 키로 하는 댓글 수 맵
   */
  async getCommentCountsByPostIds(
    postIds: number[],
  ): Promise<Map<number, number>> {
    if (postIds.length === 0) {
      return new Map();
    }

    const comments = await this.commentRepository
      .createQueryBuilder('comment')
      .select('comment.postId', 'postId')
      .addSelect('COUNT(comment.id)', 'count')
      .where('comment.postId IN (:...postIds)', { postIds })
      .groupBy('comment.postId')
      .getRawMany();

    console.log('Raw query result:', JSON.stringify(comments, null, 2));

    const commentCountMap = new Map<number, number>();

    // 모든 게시글에 대해 초기값 0 설정
    postIds.forEach((id) => commentCountMap.set(id, 0));

    // 댓글이 있는 게시글의 카운트 설정
    comments.forEach((comment) => {
      commentCountMap.set(parseInt(comment.postId), parseInt(comment.count));
    });

    return commentCountMap;
  }

  /**
   * userUuid로 userId 조회 (user.service로 추후 이동 예정)
   * @param userUuid 사용자 UUID
   * @returns 사용자 ID
   */
  async getUserIdByUuid(userUuid: string): Promise<number> {
    const user = await this.userRepository.findOne({
      where: { userUuid },
      select: ['id'],
    });

    if (!user) {
      throw new NotFoundException(
        `UUID ${userUuid}에 해당하는 사용자를 찾을 수 없습니다.`,
      );
    }

    return user.id;
  }
}
