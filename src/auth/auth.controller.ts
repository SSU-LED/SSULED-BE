import { Controller, Get, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';

export interface SocialRequest {
  user: {
    socialId: string;
    nickname: string;
    profileImage: string;
    socialProvider: string;
  };
}

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('login/kakao')
  @UseGuards(AuthGuard('kakao'))
  async kakaoAuth() {
    console.log('kakao login triggered');
  }

  /* Get kakao Auth Callback */
  @Get('kakao/callback')
  @UseGuards(AuthGuard('kakao'))
  async kakaoAuthCallback(
    @Req() req: SocialRequest,
    @Res() res: Response, // : Promise<KakaoLoginAuthOutputDto>
  ) {
    const { user } = req;
    console.log(user);
    // return res.send(user);
    return this.authService.kakaoLogin(req, res);
  }

  @Get('login/naver')
  @UseGuards(AuthGuard('naver'))
  async naverAuth() {
    console.log('naver login triggered');
  }

  /* Get naver Auth Callback */
  @Get('naver/callback')
  @UseGuards(AuthGuard('naver'))
  async naverAuthCallback(
    @Req() req: SocialRequest,
    @Res() res: Response, // : Promise<NaverLoginAuthOutputDto>
  ) {
    const { user } = req;
    console.log(user);
    // return res.send(user);
    return this.authService.naverLogin(req, res);
  }
}
