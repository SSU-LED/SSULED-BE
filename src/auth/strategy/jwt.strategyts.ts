import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Request } from 'express';
import { Strategy, ExtractJwt } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      // Authorization 헤더의 Bearer 토큰에서 JWT를 추출
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secreatOrKey: process.env.JWT_ACCESS_TOKEN_SECRET,
      passReqToCallback: true, // validate 함수에서 req 객체를 사용 가능하게 함
    });
  }

  async validate(req: Request, payload: any) {
    const { userUuid } = payload;
    if (!userUuid) {
      throw new UnauthorizedException('Invalid token');
    }
    // 검증된 토큰의 정보를 req.user에 할당
    req.user = { userUuid };
    return { userUuid };
  }
}
