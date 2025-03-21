import { applyDecorators } from '@nestjs/common';
import {
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiQuery,
} from '@nestjs/swagger';
import { BodyPartEnum } from '../types/body-part.enum';

export function ApiUploadImage() {
  return applyDecorators(
    ApiOperation({
      summary: '이미지 업로드',
      description: 'S3 Bucket에 이미지 파일을 업로드합니다.',
    }),
    ApiConsumes('multipart/form-data'),
    ApiBody({
      schema: {
        type: 'object',
        properties: {
          image: {
            type: 'string',
            format: 'binary',
            description: '업로드할 이미지 파일 (jpg, jpeg, png, gif만 가능)',
          },
        },
      },
    }),
    ApiResponse({
      status: 201,
      description: '이미지가 성공적으로 업로드됨',
      schema: {
        type: 'object',
        properties: {
          imageUrl: {
            type: 'string',
            example:
              'https://ssuled-bucket.s3.amazonaws.com/images/example-image.jpg',
          },
          message: {
            type: 'string',
            example: '이미지가 업로드되었습니다.',
          },
        },
      },
    }),
    ApiResponse({
      status: 400,
      description: '잘못된 요청',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '이미지 업로드 실패: The bucket does not allow ACLs',
          },
          error: {
            type: 'string',
            example: 'Bad Request',
          },
          statusCode: {
            type: 'number',
            example: 400,
          },
        },
      },
    }),
  );
}

export function ApiDeleteImage() {
  return applyDecorators(
    ApiOperation({
      summary: '이미지 삭제',
      description: '업로드된 이미지를 S3에서 삭제합니다.',
    }),
    ApiParam({
      name: 'url',
      description: '삭제할 이미지 URL',
      required: true,
    }),
    ApiResponse({
      status: 200,
      description: '이미지가 성공적으로 삭제됨',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '이미지가 삭제되었습니다.',
          },
        },
      },
    }),
    ApiResponse({
      status: 400,
      description: '잘못된 요청',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '이미지 삭제 실패: The specified key does not exist',
          },
          error: {
            type: 'string',
            example: 'Bad Request',
          },
          statusCode: {
            type: 'number',
            example: 400,
          },
        },
      },
    }),
  );
}

export function ApiCreatePost() {
  return applyDecorators(
    ApiOperation({
      summary: '게시글 생성',
      description: '새로운 게시글을 생성합니다.',
    }),
    ApiBody({
      schema: {
        type: 'object',
        required: ['userUuid', 'content'],
        properties: {
          userUuid: {
            type: 'string',
            description: '조회할 사용자 UUID',
            example: '123e4567-e89b-12d3-a456-426614174000',
          },
          content: {
            type: 'string',
            description: '게시글 내용',
            example: '처음으로 헬스장에 가봤는데 너무 좋았어요!',
          },
          imageUrl: {
            type: 'array',
            items: {
              type: 'string',
            },
            description: '게시글 이미지 URL 배열',
            example: [
              'https://ssuled-bucket.s3.amazonaws.com/images/example-image1.jpg',
            ],
          },
          bodyPart: {
            type: 'array',
            items: {
              type: 'string',
              enum: Object.values(BodyPartEnum),
            },
            description: '운동한 신체부위 배열',
            example: [
              BodyPartEnum.CHEST,
              BodyPartEnum.SHOULDERS_ARMS,
              BodyPartEnum.BACK,
            ],
          },
          duration: {
            type: 'number',
            description: '운동한 시간 (분 단위)',
            example: 90,
          },
        },
      },
    }),
    ApiResponse({
      status: 201,
      description: '게시글이 성공적으로 생성됨',
      schema: {
        type: 'object',
        properties: {
          userUuid: {
            type: 'string',
            example: '123e4567-e89b-12d3-a456-426614174000',
          },
          content: {
            type: 'string',
            example: '처음으로 헬스장에 가봤는데 너무 좋았어요!',
          },
          imageUrl: {
            type: 'array',
            items: {
              type: 'string',
            },
            example: [
              'https://ssuled-bucket.s3.amazonaws.com/images/example-image1.jpg',
            ],
          },
          bodyPart: {
            type: 'array',
            items: {
              type: 'string',
              enum: Object.values(BodyPartEnum),
            },
            example: [
              BodyPartEnum.CHEST,
              BodyPartEnum.SHOULDERS_ARMS,
              BodyPartEnum.BACK,
            ],
          },
          duration: {
            type: 'number',
            example: 90,
          },
          createdAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-19T10:41:07.528Z',
          },
          updatedAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-19T10:41:07.528Z',
          },
          title: {
            type: 'string',
            nullable: true,
            example: null,
          },
          id: {
            type: 'number',
            example: 6,
          },
        },
      },
    }),
    ApiResponse({
      status: 400,
      description: '잘못된 요청',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'array',
            example: [
              'content should not be empty',
              'userUuid must be a UUID format',
            ],
          },
          error: {
            type: 'string',
            example: 'Bad Request',
          },
          statusCode: {
            type: 'number',
            example: 400,
          },
        },
      },
    }),
  );
}

export function ApiGetAllPosts() {
  return applyDecorators(
    ApiOperation({
      summary: '모든 게시글 조회',
      description: '모든 게시글 목록을 조회합니다.',
    }),
    ApiQuery({
      name: 'page',
      required: false,
      description: '페이지 번호 (default: 1)',
      type: 'number',
      example: 1,
    }),
    ApiQuery({
      name: 'limit',
      required: false,
      description: '페이지당 게시글 수 (default: 24)',
      type: 'number',
      example: 24,
    }),
    ApiQuery({
      name: 'userUuid',
      required: false,
      description: '사용자 UUID (임시)',
      type: 'string',
      example: '123e4567-e89b-12d3-a456-426614174000',
    }),
    ApiResponse({
      status: 200,
      description: '게시글 목록 조회 성공',
      schema: {
        type: 'object',
        properties: {
          data: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: {
                  type: 'number',
                  example: 1,
                },
                content: {
                  type: 'string',
                  example: '처음으로 헬스장에 가봤는데 너무 좋았어요!',
                },
                imageUrl: {
                  type: 'array',
                  items: {
                    type: 'string',
                  },
                  example: [
                    'https://ssuled-bucket.s3.amazonaws.com/images/example-image1.jpg',
                  ],
                },
                bodyPart: {
                  type: 'array',
                  items: {
                    type: 'string',
                    enum: Object.values(BodyPartEnum),
                  },
                  example: [
                    BodyPartEnum.CHEST,
                    BodyPartEnum.SHOULDERS_ARMS,
                    BodyPartEnum.BACK,
                  ],
                },
                duration: {
                  type: 'number',
                  example: 90,
                },
                createdAt: {
                  type: 'string',
                  format: 'date-time',
                  example: '2025-03-17T09:00:00.000Z',
                },
                updatedAt: {
                  type: 'string',
                  format: 'date-time',
                  example: '2025-03-19T09:00:00.000Z',
                },
                likeCount: {
                  type: 'number',
                  example: 15,
                  description: '좋아요 수',
                },
                commentCount: {
                  type: 'number',
                  example: 5,
                  description: '댓글 수',
                },
              },
            },
          },
          meta: {
            type: 'object',
            properties: {
              totalItems: {
                type: 'number',
                example: 100,
              },
              itemsPerPage: {
                type: 'number',
                example: 24,
              },
              totalPages: {
                type: 'number',
                example: 5,
              },
              currentPage: {
                type: 'number',
                example: 1,
              },
            },
          },
        },
      },
    }),
  );
}

export function ApiGetPostById() {
  return applyDecorators(
    ApiOperation({
      summary: '게시글 상세 조회',
      description: '특정 ID의 게시글을 조회합니다.',
    }),
    ApiParam({
      name: 'postId',
      description: '조회할 게시글 ID',
      required: true,
      type: 'string',
    }),
    ApiQuery({
      name: 'userUuid',
      description: '현재 사용자 UUID (좋아요 상태 확인용)',
      example: '123e4567-e89b-12d3-a456-426614174000',
      required: false,
      type: 'string',
    }),
    ApiResponse({
      status: 200,
      description: '게시글 조회 성공',
      schema: {
        type: 'object',
        properties: {
          id: {
            type: 'number',
            example: 1,
          },
          content: {
            type: 'string',
            example: '처음으로 헬스장에 가봤는데 너무 좋았어요!',
          },
          imageUrl: {
            type: 'array',
            items: {
              type: 'string',
            },
            example: [
              'https://ssuled-bucket.s3.amazonaws.com/images/example-image1.jpg',
            ],
          },
          bodyPart: {
            type: 'array',
            items: {
              type: 'string',
              enum: Object.values(BodyPartEnum),
            },
            example: ['CHEST', 'SHOULDERS_ARMS', 'BACK'],
          },
          duration: {
            type: 'number',
            example: 90,
          },
          createdAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-17T09:00:00.000Z',
          },
          updatedAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-19T09:00:00.000Z',
          },
          likeCount: {
            type: 'number',
            example: 15,
            description: '좋아요 수',
          },
          commentCount: {
            type: 'number',
            example: 5,
            description: '댓글 수',
          },
          userLiked: {
            type: 'boolean',
            example: true,
            description: '현재 사용자의 좋아요 여부',
          },
          comments: {
            type: 'array',
            description: '댓글 목록',
            items: {
              type: 'object',
              properties: {
                id: {
                  type: 'number',
                  example: 1,
                },
                content: {
                  type: 'string',
                  example: '오운완 좋아요!',
                },
                userUuid: {
                  type: 'string',
                  example: '123e4567-e89b-12d3-a456-426614174001',
                },
                userName: {
                  type: 'string',
                  example: '재굴TV',
                },
                userProfileImage: {
                  type: 'string',
                  example:
                    'https://ssuled-bucket.s3.amazonaws.com/profiles/user1.jpg',
                },
                createdAt: {
                  type: 'string',
                  format: 'date-time',
                  example: '2025-03-18T10:00:00.000Z',
                },
                updatedAt: {
                  type: 'string',
                  format: 'date-time',
                  example: '2025-03-18T10:00:00.000Z',
                },
              },
            },
          },
        },
      },
    }),
    ApiResponse({
      status: 404,
      description: '게시글을 찾을 수 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '해당 ID의 게시글을 찾을 수 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Not Found',
          },
          statusCode: {
            type: 'number',
            example: 404,
          },
        },
      },
    }),
  );
}

export function ApiUpdatePost() {
  return applyDecorators(
    ApiOperation({
      summary: '게시글 수정',
      description: '특정 ID의 게시글을 수정합니다.',
    }),
    ApiParam({
      name: 'postId',
      description: '수정할 게시글 ID',
      required: true,
      type: 'string',
    }),
    ApiBody({
      schema: {
        type: 'object',
        properties: {
          content: {
            type: 'string',
            description: '게시글 내용',
            example: '처음으로 헬스장에 가봤는데 너무 좋았어요! 오운완! 😎',
          },
          imageUrl: {
            type: 'array',
            items: {
              type: 'string',
            },
            description: '게시글 이미지 URL 배열',
            example: [
              'https://ssuled-bucket.s3.amazonaws.com/images/updated-image1.jpg',
            ],
          },
          bodyPart: {
            type: 'array',
            items: {
              type: 'string',
              enum: Object.values(BodyPartEnum),
            },
            description: '운동한 신체부위 배열',
            example: [
              BodyPartEnum.CHEST,
              BodyPartEnum.SHOULDERS_ARMS,
              BodyPartEnum.CORE,
            ],
          },
          duration: {
            type: 'number',
            description: '운동한 시간 (분 단위)',
            example: 120,
          },
        },
      },
    }),
    ApiResponse({
      status: 200,
      description: '게시글이 성공적으로 수정됨',
      schema: {
        type: 'object',
        properties: {
          id: {
            type: 'number',
            example: 1,
          },
          content: {
            type: 'string',
            example: '처음으로 헬스장에 가봤는데 너무 좋았어요! 오운완! 😎',
          },
          imageUrl: {
            type: 'array',
            items: {
              type: 'string',
            },
            example: [
              'https://ssuled-bucket.s3.amazonaws.com/images/updated-image1.jpg',
            ],
          },
          bodyPart: {
            type: 'array',
            items: {
              type: 'string',
              enum: Object.values(BodyPartEnum),
            },
            example: [
              BodyPartEnum.CHEST,
              BodyPartEnum.SHOULDERS_ARMS,
              BodyPartEnum.CORE,
            ],
          },
          duration: {
            type: 'number',
            example: 120,
          },
          updatedAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-19T10:30:00.000Z',
          },
        },
      },
    }),
    ApiResponse({
      status: 404,
      description: '게시글을 찾을 수 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '해당 ID의 게시글을 찾을 수 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Not Found',
          },
          statusCode: {
            type: 'number',
            example: 404,
          },
        },
      },
    }),
    ApiResponse({
      status: 400,
      description: 'Validation 오류',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'array',
            example: ['content must be a string', 'imageUrl must be an array'],
          },
          error: {
            type: 'string',
            example: 'Bad Request',
          },
          statusCode: {
            type: 'number',
            example: 400,
          },
        },
      },
    }),
  );
}

export function ApiCreateComment() {
  return applyDecorators(
    ApiOperation({
      summary: '댓글 생성',
      description: '게시글에 새로운 댓글을 작성합니다.',
    }),
    ApiBody({
      schema: {
        type: 'object',
        properties: {
          userUuid: {
            type: 'string',
            format: 'uuid',
            description: '댓글 작성자 UUID',
            example: '123e4567-e89b-12d3-a456-426614174000',
          },
          postId: {
            type: 'integer',
            description: '댓글을 작성할 게시글 ID',
            example: 1,
          },
          content: {
            type: 'string',
            description: '댓글 내용',
            example: '오운완 축하합니다! 💪',
          },
        },
        required: ['userUuid', 'postId', 'content'],
      },
    }),
    ApiResponse({
      status: 201,
      description: '댓글이 성공적으로 생성됨',
      schema: {
        type: 'object',
        properties: {
          id: {
            type: 'integer',
            example: 1,
          },
          content: {
            type: 'string',
            example: '오운완 축하합니다! 💪',
          },
          userUuid: {
            type: 'string',
            example: '123e4567-e89b-12d3-a456-426614174000',
          },
          postId: {
            type: 'integer',
            example: 1,
          },
          createdAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-20T10:30:00Z',
          },
          updatedAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-20T10:30:00Z',
          },
        },
      },
    }),
    ApiResponse({
      status: 400,
      description: '잘못된 요청',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'array',
            example: [
              'content must be a string',
              'content should not be empty',
              'userUuid must be a string',
              'postId must be a number',
            ],
          },
          error: {
            type: 'string',
            example: 'Bad Request',
          },
          statusCode: {
            type: 'number',
            example: 400,
          },
        },
      },
    }),
    ApiResponse({
      status: 404,
      description: '게시글 또는 사용자를 찾을 수 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '해당 ID의 게시글을 찾을 수 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Not Found',
          },
          statusCode: {
            type: 'number',
            example: 404,
          },
        },
      },
    }),
  );
}

export function ApiDeletePost() {
  return applyDecorators(
    ApiOperation({
      summary: '게시글 삭제',
      description: '특정 ID의 게시글을 삭제합니다.',
    }),
    ApiParam({
      name: 'postId',
      description: '삭제할 게시글 ID',
      required: true,
      type: 'string',
    }),
    ApiResponse({
      status: 200,
      description: '게시글이 성공적으로 삭제됨',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '게시글이 성공적으로 삭제되었습니다.',
          },
        },
      },
    }),
    ApiResponse({
      status: 404,
      description: '게시글을 찾을 수 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '해당 ID의 게시글을 찾을 수 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Not Found',
          },
          statusCode: {
            type: 'number',
            example: 404,
          },
        },
      },
    }),
  );
}

export function ApiUpdateComment() {
  return applyDecorators(
    ApiOperation({
      summary: '댓글 수정',
      description: '특정 ID의 댓글을 수정합니다.',
    }),
    ApiParam({
      name: 'commentId',
      description: '수정할 댓글 ID',
      required: true,
      type: 'string',
    }),
    ApiBody({
      schema: {
        type: 'object',
        properties: {
          content: {
            type: 'string',
            description: '댓글 내용',
            example: '정말 멋진 운동이네요! 👍',
          },
        },
        required: ['content'],
      },
    }),
    ApiResponse({
      status: 200,
      description: '댓글이 성공적으로 수정됨',
      schema: {
        type: 'object',
        properties: {
          id: {
            type: 'integer',
            example: 1,
          },
          content: {
            type: 'string',
            example: '정말 멋진 운동이네요! 👍',
          },
          userUuid: {
            type: 'string',
            example: '123e4567-e89b-12d3-a456-426614174000',
          },
          postId: {
            type: 'integer',
            example: 1,
          },
          createdAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-20T10:30:00Z',
          },
          updatedAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-20T10:35:00Z',
          },
        },
      },
    }),
    ApiResponse({
      status: 404,
      description: '댓글을 찾을 수 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '해당 ID의 댓글을 찾을 수 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Not Found',
          },
          statusCode: {
            type: 'number',
            example: 404,
          },
        },
      },
    }),
    ApiResponse({
      status: 400,
      description: 'Validation 오류',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'array',
            example: [
              'content must be a string',
              'content should not be empty',
            ],
          },
          error: {
            type: 'string',
            example: 'Bad Request',
          },
          statusCode: {
            type: 'number',
            example: 400,
          },
        },
      },
    }),
    ApiResponse({
      status: 403,
      description: '권한 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '이 댓글을 수정할 권한이 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Forbidden',
          },
          statusCode: {
            type: 'number',
            example: 403,
          },
        },
      },
    }),
  );
}

export function ApiGetAllComments() {
  return applyDecorators(
    ApiOperation({
      summary: '모든 댓글 조회',
      description: '특정 게시글의 모든 댓글을 조회합니다.',
    }),
    ApiParam({
      name: 'postId',
      description: '댓글을 조회할 게시글 ID',
      required: true,
      type: 'string',
    }),
    ApiQuery({
      name: 'page',
      required: false,
      description: '페이지 번호 (default: 1)',
      type: 'number',
      example: 1,
    }),
    ApiQuery({
      name: 'limit',
      required: false,
      description: '페이지당 댓글 수 (default: 10)',
      type: 'number',
      example: 10,
    }),
    ApiResponse({
      status: 200,
      description: '댓글 목록 조회 성공',
      schema: {
        type: 'object',
        properties: {
          data: {
            type: 'array',
            items: {
              type: 'object',
              properties: {
                id: {
                  type: 'number',
                  example: 1,
                },
                content: {
                  type: 'string',
                  example: '멋진 운동이네요!',
                },
                postId: {
                  type: 'number',
                  example: 1,
                },
                createdAt: {
                  type: 'string',
                  format: 'date-time',
                  example: '2025-03-18T10:00:00.000Z',
                },
                updatedAt: {
                  type: 'string',
                  format: 'date-time',
                  example: '2025-03-18T10:00:00.000Z',
                },
                user: {
                  type: 'object',
                  properties: {
                    userUuid: {
                      type: 'string',
                      example: '123e4567-e89b-12d3-a456-426614174001',
                    },
                    nickname: {
                      type: 'string',
                      example: '재굴TV',
                    },
                    profileImage: {
                      type: 'string',
                      example:
                        'https://ssuled-bucket.s3.amazonaws.com/profiles/user1.jpg',
                    },
                  },
                },
              },
            },
          },
          meta: {
            type: 'object',
            properties: {
              totalItems: {
                type: 'number',
                example: 25,
              },
              itemsPerPage: {
                type: 'number',
                example: 10,
              },
              totalPages: {
                type: 'number',
                example: 3,
              },
              currentPage: {
                type: 'number',
                example: 1,
              },
            },
          },
        },
      },
    }),
    ApiResponse({
      status: 404,
      description: '댓글을 찾을 수 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '해당 ID의 댓글을 찾을 수 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Not Found',
          },
          statusCode: {
            type: 'number',
            example: 404,
          },
        },
      },
    }),
  );
}

export function ApiGetComment() {
  return applyDecorators(
    ApiOperation({
      summary: '댓글 상세 조회',
      description: '특정 ID의 댓글을 상세하게 조회합니다.',
    }),
    ApiParam({
      name: 'commentId',
      description: '조회할 댓글 ID',
      required: true,
      type: 'string',
    }),
    ApiResponse({
      status: 200,
      description: '댓글 상세 조회 성공',
      schema: {
        type: 'object',
        properties: {
          id: {
            type: 'number',
            example: 1,
          },
          content: {
            type: 'string',
            example: '멋진 운동이네요!',
          },
          userUuid: {
            type: 'string',
            example: '123e4567-e89b-12d3-a456-426614174001',
          },
          postId: {
            type: 'number',
            example: 1,
          },
          createdAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-18T10:00:00.000Z',
          },
          updatedAt: {
            type: 'string',
            format: 'date-time',
            example: '2025-03-18T10:00:00.000Z',
          },
        },
      },
    }),
    ApiResponse({
      status: 404,
      description: '댓글을 찾을 수 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '해당 ID의 댓글을 찾을 수 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Not Found',
          },
          statusCode: {
            type: 'number',
            example: 404,
          },
        },
      },
    }),
  );
}

export function ApiDeleteComment() {
  return applyDecorators(
    ApiOperation({
      summary: '댓글 삭제',
      description: '특정 ID의 댓글을 삭제합니다.',
    }),
    ApiParam({
      name: 'commentId',
      description: '삭제할 댓글 ID',
      required: true,
      type: 'string',
    }),
    ApiResponse({
      status: 200,
      description: '댓글이 성공적으로 삭제됨',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '댓글이 성공적으로 삭제되었습니다.',
          },
        },
      },
    }),
    ApiResponse({
      status: 404,
      description: '댓글을 찾을 수 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '해당 ID의 댓글을 찾을 수 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Not Found',
          },
          statusCode: {
            type: 'number',
            example: 404,
          },
        },
      },
    }),
    ApiResponse({
      status: 403,
      description: '권한 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '이 댓글을 삭제할 권한이 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Forbidden',
          },
          statusCode: {
            type: 'number',
            example: 403,
          },
        },
      },
    }),
  );
}

export function ApiCreateLike() {
  return applyDecorators(
    ApiOperation({
      summary: '좋아요 추가',
      description: '게시글에 좋아요를 추가합니다.',
    }),
    ApiBody({
      schema: {
        type: 'object',
        properties: {
          userUuid: {
            type: 'string',
            format: 'uuid',
            description: '좋아요를 추가할 사용자 UUID',
            example: '123e4567-e89b-12d3-a456-426614174000',
          },
          postId: {
            type: 'integer',
            description: '좋아요를 추가할 게시글 ID',
            example: 1,
          },
        },
        required: ['userUuid', 'postId'],
      },
    }),
    ApiResponse({
      status: 201,
      description: '좋아요가 성공적으로 추가됨',
      schema: {
        type: 'object',
        properties: {
          id: {
            type: 'integer',
            example: 1,
          },
          likeCount: {
            type: 'integer',
            example: 15,
            description: '게시글의 전체 좋아요 수',
          },
        },
      },
    }),
    ApiResponse({
      status: 400,
      description: '잘못된 요청',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'array',
            example: ['userUuid must be a UUID', 'postId must be a number'],
          },
          error: {
            type: 'string',
            example: 'Bad Request',
          },
          statusCode: {
            type: 'number',
            example: 400,
          },
        },
      },
    }),
    ApiResponse({
      status: 404,
      description: '사용자를 찾을 수 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example:
              'UUID 123e4567-e89b-12d3-a456-426614174000에 해당하는 사용자를 찾을 수 없습니다.',
          },
          error: {
            type: 'string',
            example: 'Not Found',
          },
          statusCode: {
            type: 'number',
            example: 404,
          },
        },
      },
    }),
    ApiResponse({
      status: 409,
      description: '이미 좋아요한 게시글',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '이미 좋아요한 게시글입니다.',
          },
          error: {
            type: 'string',
            example: 'Conflict',
          },
          statusCode: {
            type: 'number',
            example: 409,
          },
        },
      },
    }),
  );
}

export function ApiCheckLikeStatus() {
  return applyDecorators(
    ApiOperation({
      summary: '좋아요 상태 확인',
      description: '사용자가 특정 게시글에 좋아요했는지 확인합니다.',
    }),
    ApiParam({
      name: 'postId',
      description: '확인할 게시글 ID',
      required: true,
      type: 'string',
    }),
    ApiParam({
      name: 'userUuid',
      description: '확인할 사용자 UUID',
      example: '123e4567-e89b-12d3-a456-426614174000',
      required: true,
      type: 'string',
    }),
    ApiResponse({
      status: 200,
      description: '좋아요 상태 확인 성공',
      schema: {
        type: 'object',
        properties: {
          liked: {
            type: 'boolean',
            example: true,
            description: '좋아요 여부',
          },
        },
      },
    }),
  );
}

export function ApiDeleteLike() {
  return applyDecorators(
    ApiOperation({
      summary: '게시글 좋아요 삭제',
      description: '특정 게시글에 대한 사용자의 좋아요를 삭제합니다.',
    }),
    ApiParam({
      name: 'postId',
      description: '게시글 ID',
      required: true,
      type: 'string',
    }),
    ApiParam({
      name: 'userUuid',
      description: '사용자 UUID',
      example: '123e4567-e89b-12d3-a456-426614174000',
      required: true,
      type: 'string',
    }),
    ApiResponse({
      status: 200,
      description: '좋아요가 성공적으로 삭제됨',
      schema: {
        type: 'object',
        properties: {
          success: {
            type: 'boolean',
            example: true,
          },
          likeCount: {
            type: 'number',
            example: 14,
            description: '업데이트된 게시글의 전체 좋아요 수',
          },
        },
      },
    }),
    ApiResponse({
      status: 404,
      description: '좋아요를 찾을 수 없음',
      schema: {
        type: 'object',
        properties: {
          message: {
            type: 'string',
            example: '해당 게시글에 좋아요를 하지 않았습니다.',
          },
          error: {
            type: 'string',
            example: 'Not Found',
          },
          statusCode: {
            type: 'number',
            example: 404,
          },
        },
      },
    }),
  );
}
