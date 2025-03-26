import { Auth } from '@/entities/auth.entity';
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { SocialRequest } from './auth.controller';
import { Request, Response } from 'express';
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
    res.setHeader('accessToken', `Bearer ${access_token}`);
    res.setHeader('refreshToken', refresh_token);
    return res.json({
      ok: true,
      message: '로그인 성공',
    });
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

  // refreshToken으로 accessToken 재발급
  async RefreshToken(req: Request, res: Response) {
    const refreshToken = req.headers['authorization']?.replace('Bearer ', '');

    if (!refreshToken) {
      return res.status(401).json({ ok: false, message: '리프레시 토큰 없음' });
    }

    try {
      // 1. 리프레시 토큰 유효성 검사
      const payload = await this.jwtService.verifyAsync(refreshToken, {
        secret: process.env.JWT_REFRESH_TOKEN_SECRET,
      });

      const userId = await this.userService.findOneById(payload.userUuid);

      if (!userId) {
        return res.status(401).json({ ok: false, message: '유효하지 않음' });
      }

      // 2. DB에 저장된 refreshToken과 비교
      const auth = await this.authRepository.findOne({
        where: { userId },
      });

      if (!auth || auth.refreshToken !== refreshToken) {
        return res
          .status(401)
          .json({ ok: false, message: '리프레시 토큰 불일치' });
      }

      // 3. 새 accessToken 발급
      const newAccessToken = this.jwtService.sign(
        {
          userUuid: payload.userUuid,
        },
        {
          secret: process.env.JWT_ACCESS_TOKEN_SECRET,
          expiresIn: '30m',
        },
      );

      // 리프레시 토큰 만료 여부 확인
      const nowInSec = Math.floor(Date.now() / 1000);
      let newRefreshToken = null;

      if (payload.exp && payload.exp < nowInSec) {
        // refreshToken도 만료 => 새 refreshToken 재발급
        newRefreshToken = this.jwtService.sign(
          { userUuid: payload.userUuid },
          {
            secret: process.env.JWT_REFRESH_TOKEN_SECRET,
            expiresIn: '14d',
          },
        );

        auth.refreshToken = newRefreshToken;
        await this.authRepository.save(auth);
      }

      // 응답 헤더에 토큰 세팅
      res.setHeader('accessToken', `Bearer ${newAccessToken}`);
      if (newRefreshToken) {
        res.setHeader('refreshToken', newRefreshToken);
      }

      return res.json({
        ok: true,
        message: newRefreshToken
          ? 'accessToken 및 refreshToken 재발급 완료'
          : 'accessToken 재발급 완료',
      });
    } catch (error) {
      console.log(error);
      return res
        .status(401)
        .json({ ok: false, message: '리프레시 토큰 만료 혹은 잘못됨' });
    }
  }
}
