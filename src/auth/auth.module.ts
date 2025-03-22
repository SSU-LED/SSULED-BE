import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { Auth } from '@/entities/auth.entity';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserService } from '@/user/user.service';
import { User } from '@/entities/user.entity';
import { JwtKakaoStrategy } from './strategy/jwt-social-kakao.strategy';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { JwtNaverStrategy } from './strategy/jwt-social-naver.strategy';

@Module({
  imports: [
    TypeOrmModule.forFeature([Auth, User]),
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_ACCESS_TOKEN_SECRET, // 환경변수나 config로 관리 추천!
      signOptions: { expiresIn: '30m' },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, UserService, JwtKakaoStrategy, JwtNaverStrategy],
})
export class AuthModule {}
