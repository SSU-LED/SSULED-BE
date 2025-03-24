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

  async kakaoLogin(req: SocialRequest, res: Response) {
    try {
      const { user } = req;

      // 유저 중복 검사
      let findUser = await this.userService.findOneBySocialId(user.socialId);

      // 없는 유저면 DB에 유저정보 저장
      if (!findUser) {
        const uuid = uuidv4();
        findUser = await this.userService.createUser(user, uuid);
      }

      console.log(findUser);

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

      // Auth 정보 DB에 저장(기존 회원이면 update, 신규회원이면 save? 아직 암호화 X)
      const userId = await this.userService.findOneById(findUser.userUuid);
      const findAuth = await this.authRepository.create({
        userId,
        refreshToken: refresh_token,
      });
      await this.authRepository.save(findAuth);

      // 쿠키 설정
      const now = new Date();
      now.setDate(now.getDate() + +'14d');
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
    } catch (error) {
      console.log(error);
      return { ok: false, error: '구글 로그인 인증을 실패하였습니다.' };
    }
  }

  // naver login
  async naverLogin(req: SocialRequest, res: Response) {
    try {
      const { user } = req;

      // 유저 중복 검사
      let findUser = await this.userService.findOneBySocialId(user.socialId);

      // 없는 유저면 DB에 유저정보 저장
      if (!findUser) {
        const uuid = uuidv4();
        findUser = await this.userService.createUser(user, uuid);
      }

      console.log(findUser);

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

      // Auth 정보 DB에 저장(기존 회원이면 update, 신규회원이면 save? 아직 암호화 X)
      const userId = await this.userService.findOneById(findUser.userUuid);
      const findAuth = await this.authRepository.create({
        userId,
        refreshToken: refresh_token,
      });
      await this.authRepository.save(findAuth);

      // 쿠키 설정
      const now = new Date();
      now.setDate(now.getDate() + +'14d');
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
    } catch (error) {
      console.log(error);
      return { ok: false, error: '구글 로그인 인증을 실패하였습니다.' };
    }
  }
}
