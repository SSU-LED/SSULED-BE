import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtAccessTokenGuard extends AuthGuard('access_token') {
  constructor(private readonly authService: AuthService) {
    super();
  }

  handleRequest(err, user, info, context) {
    if (info && info.name === 'TokenExpiredError') {
      // 엑세스 토큰이 만료되었을 경우 리프레시 토큰을 이용해 새로운 엑세스 토큰을 갱신하는 처리 추가
      throw new Error('엑세스 토큰 만료됨. 리프레시 토큰으로 갱신해주세요.');
    }
    return super.handleRequest(err, user, info, context);
  }
}
