import { DataSource } from 'typeorm';
import { Seeder } from 'typeorm-extension';
import { Auth } from '@/entities/auth.entity';
import { User } from '@/entities/user.entity';
import { v4 as uuidv4 } from 'uuid';
import { Logger } from 'winston';
import { LoggerService } from '@/utils/logger.service';

export class AuthSeeder implements Seeder {
  private readonly logger: Logger = LoggerService.getInstance().logger;

  public async run(dataSource: DataSource): Promise<void> {
    const authRepository = dataSource.getRepository(Auth);
    const userRepository = dataSource.getRepository(User);

    // 모든 사용자 가져오기
    const users = await userRepository.find();

    if (users.length === 0) {
      this.logger.warn('사용자가 없습니다. 인증 정보 생성을 건너뜁니다.');
      return;
    }

    for (const user of users) {
      // 이미 존재하는 인증 정보인지 확인
      const existingAuth = await authRepository.findOne({
        where: { userId: user.id },
      });

      if (existingAuth) {
        this.logger.info(
          `사용자 ID ${user.id}의 인증 정보가 이미 존재합니다. 건너뜁니다.`,
        );
        continue;
      }

      // 새 인증 정보 생성
      const auth = authRepository.create({
        userId: user.id,
        // accessToken: `access_${uuidv4()}`,
        refreshToken: `refresh_${uuidv4()}`,
      });

      await authRepository.save(auth);

      this.logger.info(`사용자 ID ${user.id}의 인증 정보 생성 완료`);
    }
  }
}
