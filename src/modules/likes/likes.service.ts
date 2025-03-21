import {
  Injectable,
  NotFoundException,
  ConflictException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Like } from '@/entities/like.entity';
import { CreateLikeDto } from './dto/create-like.dto';
import { User } from '@/entities/user.entity';

@Injectable()
export class LikesService {
  constructor(
    @InjectRepository(Like)
    private likeRepository: Repository<Like>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
  ) {}

  /**
   * 좋아요 추가
   * @param createLikeDto 좋아요 생성 정보
   * @returns 생성된 좋아요 정보와 좋아요 수
   */
  async createLike(createLikeDto: CreateLikeDto) {
    // 이미 좋아요한 게시글인지 확인
    const existingLike = await this.likeRepository.findOne({
      where: {
        postId: createLikeDto.postId,
        userUuid: createLikeDto.userUuid,
      },
    });

    if (existingLike) {
      throw new ConflictException('이미 좋아요한 게시글입니다.');
    }

    // 사용자 정보 조회
    const userId = await this.getUserIdByUuid(createLikeDto.userUuid);

    // 좋아요 생성
    const like = this.likeRepository.create({
      ...createLikeDto,
      userId,
    });

    await this.likeRepository.save(like);

    // 게시글의 전체 좋아요 수 조회
    const likeCount = await this.getLikeCountByPostId(createLikeDto.postId);

    return {
      id: like.id,
      likeCount,
    };
  }

  /**
   * 게시글의 좋아요 수 조회
   * @param postId 게시글 ID
   * @returns 좋아요 수
   */
  async getLikeCountByPostId(postId: number): Promise<number> {
    return this.likeRepository.count({
      where: { postId },
    });
  }

  /**
   * 사용자가 게시글에 좋아요했는지 확인
   * @param userUuid 사용자 UUID
   * @param postId 게시글 ID
   * @returns 좋아요 여부와 좋아요 ID
   */
  async checkLikeStatus(userUuid: string, postId: number) {
    const like = await this.likeRepository.findOne({
      where: {
        userUuid,
        postId,
      },
    });

    return {
      liked: !!like,
    };
  }

  /**
   * 게시글 좋아요 삭제
   * @param postId 게시글 ID
   * @param userUuid 사용자 UUID
   * @returns 삭제 성공 메시지와 업데이트된 좋아요 수
   */
  async removeLike(postId: number, userUuid: string) {
    const like = await this.likeRepository.findOne({
      where: {
        postId,
        userUuid,
      },
    });

    if (!like) {
      throw new NotFoundException('해당 게시글에 좋아요를 하지 않았습니다.');
    }

    await this.likeRepository.delete(like.id);

    // 업데이트된 좋아요 수 조회
    const likeCount = await this.getLikeCountByPostId(postId);

    return {
      success: true,
      likeCount,
    };
  }

  /**
   * 여러 게시글의 좋아요 수 조회
   * @param postIds 게시글 ID 배열
   * @returns 게시글 ID를 키로 하는 좋아요 수 맵
   */
  async getLikeCountsByPostIds(
    postIds: number[],
  ): Promise<Map<number, number>> {
    const likes = await this.likeRepository
      .createQueryBuilder('like')
      .select('like.postId', 'postId')
      .addSelect('COUNT(like.id)', 'count')
      .where('like.postId IN (:...postIds)', { postIds })
      .groupBy('like.postId')
      .getRawMany();

    const likeCountMap = new Map<number, number>();

    // 모든 게시글에 대해 초기값 0 설정
    postIds.forEach((id) => likeCountMap.set(id, 0));

    // 좋아요가 있는 게시글의 카운트 설정
    likes.forEach((like) => {
      likeCountMap.set(parseInt(like.postId), parseInt(like.count));
    });

    return likeCountMap;
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
