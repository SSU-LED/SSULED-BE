import { IsInt, IsOptional, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class FindPopularPostsDto {
  @IsInt()
  @Min(1)
  @IsOptional()
  @Type(() => Number)
  page?: number = 1;

  @IsInt()
  @Min(1)
  @IsOptional()
  @Type(() => Number)
  limit?: number = 24;
}
