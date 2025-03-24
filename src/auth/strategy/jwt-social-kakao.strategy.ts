import { SocialProvider } from '@/types/social-provider.enum';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-kakao';

@Injectable()
export class JwtKakaoStrategy extends PassportStrategy(Strategy, 'kakao') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.get('KAKAO_REST_API_KEY'),
      callbackURL: configService.get('KAKAO_REDIRECT_URL'),
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (error: any, user?: any, info?: any) => void,
  ) {
    console.log(profile);
    try {
      console.log(profile);
      const { id: kakaoId, _json } = profile;

      // 카카오 프로필 정보에서 데이터 꺼내기
      const nickname = _json.properties?.nickname;
      const profileImage = _json.properties?.profile_image;

      const user = {
        socialId: kakaoId,
        nickname,
        profileImage,
        socialProvider: SocialProvider.KAKAO,
      };
      done(null, user);
    } catch (error) {
      done(error);
    }
  }
}
