import { User } from '@/entities/user.entity';
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
@Injectable()
export class UsersService {
  constructor(@InjectRepository(User) private repo: Repository<User>) {}

  findOneBySocialId(socialId: string) {
    return this.repo.findOneBy({ socialId });
  }

  async findOneById(userUuid: string) {
    const user = await this.repo.findOne({ where: { userUuid } });
    if (!user) {
      throw new Error('not found user!');
    }
    return user.id;
  }

  createUser(user, uuid): Promise<User> {
    const newUser = this.repo.create({
      userUuid: uuid,
      nickname: user.nickname,
      profileImage: user.profileImage,
      socialProvider: user.socialProvider,
      socialId: user.socialId,
    });
    return this.repo.save(newUser);
  }
}
