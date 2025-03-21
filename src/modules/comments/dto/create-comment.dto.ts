import { IsDate, IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class CreateCommentDto {
  // temporary
  @IsString()
  @IsNotEmpty()
  userUuid: string;

  @IsNumber()
  @IsNotEmpty()
  postId: number;

  @IsString()
  @IsNotEmpty()
  content: string;

  @IsDate()
  createdAt: Date = new Date();

  @IsDate()
  updatedAt: Date = new Date();
}
