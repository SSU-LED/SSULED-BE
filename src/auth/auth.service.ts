import { Auth } from '@/entities/auth.entity';
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SocialRequest } from './auth.controller';
import { Response } from 'express';
import { UsersService } from '@/modules/users/users.service';
import { v4 as uuidv4 } from 'uuid';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(Auth) private readonly authRepository: Repository<Auth>,
    private readonly userService: UsersService,
    private readonly jwtService: JwtService,
  ) {}

  private async handleSocialLogin(user: SocialRequest['user'], res: Response) {
    // 유저 중복 검사
    let findUser = await this.userService.findOneBySocialId(user.socialId);
    if (!findUser) {
      // 없는 유저면 DB에 유저정보 저장
      const uuid = uuidv4();
      findUser = await this.userService.createUser(user, uuid);
    }

    // 카카오 가입이 되어 있는 경우 accessToken 및 refreshToken 발급
    const findUserPayload = { userUuid: findUser.userUuid };
    const access_token = await this.jwtService.sign(findUserPayload, {
      secret: process.env.JWT_ACCESS_TOKEN_SECRET,
      expiresIn: '30m',
    });

    const refresh_token = await this.jwtService.sign(findUserPayload, {
      secret: process.env.JWT_REFRESH_TOKEN_SECRET,
      expiresIn: '14d',
    });

    const userId = await this.userService.findOneById(findUser.userUuid);
    const existingAuth = await this.authRepository.findOne({
      where: { userId },
    });

    if (existingAuth) {
      existingAuth.refreshToken = refresh_token;
      await this.authRepository.save(existingAuth);
    } else {
      const newAuth = await this.authRepository.create({
        userId,
        refreshToken: refresh_token,
      });
      await this.authRepository.save(newAuth);
    }

    // 쿠키 설정 (프론트로 어떻게 넘길지 고민중)
    const now = new Date();
    now.setDate(now.getDate() + 14);
    res.cookie('frefresh_token', refresh_token, {
      expires: now,
      httpOnly: true,
      // secure: process.env.NODE_ENV === 'production' ? true : false,
      // sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    });
    return {
      ok: true,
      access_token,
    };
  }

  async kakaoLogin(req: SocialRequest, res: Response) {
    try {
      const { user } = req;
      return await this.handleSocialLogin(user, res);
    } catch (error) {
      console.log(error);
      return { ok: false, error: '카카오 로그인 인증을 실패하였습니다.' };
    }
  }

  // naver login
  async naverLogin(req: SocialRequest, res: Response) {
    try {
      const { user } = req;

      return this.handleSocialLogin(user, res);
    } catch (error) {
      console.log(error);
      return { ok: false, error: '네이버 로그인 인증을 실패하였습니다.' };
    }
  }
}
