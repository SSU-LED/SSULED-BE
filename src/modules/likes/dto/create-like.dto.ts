import { IsNotEmpty, IsNumber, IsString } from 'class-validator';

export class CreateLikeDto {
  @IsString()
  @IsNotEmpty()
  userUuid: string;

  @IsNumber()
  @IsNotEmpty()
  postId: number;
}
