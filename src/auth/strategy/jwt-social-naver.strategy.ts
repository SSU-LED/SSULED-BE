import { SocialProvider } from '@/types/social-provider.enum';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-naver';

@Injectable()
export class JwtNaverStrategy extends PassportStrategy(Strategy, 'naver') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.get('NAVER_ID'),
      clientSecret: configService.get('NAVER_SECRET'),
      callbackURL: configService.get('NAVER_REDIRECT_URL'),
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (error: any, user?: any, info?: any) => void,
  ) {
    try {
      console.log(profile);
      const { id: naverId, _json } = profile;
      const nickname = _json.nickname;
      const profileImage = _json.profile_image;

      const user = {
        socialId: naverId,
        nickname,
        profileImage,
        socialProvider: SocialProvider.NAVER,
      };
      done(null, user);
    } catch (error) {
      done(error);
    }
  }
}
