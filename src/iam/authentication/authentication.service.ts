import {
  ConflictException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { JwtService } from '@nestjs/jwt';
import { ConfigType } from '@nestjs/config';
import { Repository } from 'typeorm';

import JwtConfig from 'src/config/jwt.config';
import { ActiveUserData } from '../interfaces/active-user-data.interface';
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { User } from 'src/users/entities/user.entity';
import { HashingService } from '../hashing/hashing.service';

@Injectable()
export class AuthenticationService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
    private readonly hashingService: HashingService,
    private readonly jwtService: JwtService,
    @Inject(JwtConfig.KEY)
    private readonly jwtConfig: ConfigType<typeof JwtConfig>,
  ) {}

  async signUp(signUpDto: SignUpDto) {
    try {
      const user = this.userRepository.create();

      user.email = signUpDto.email;
      user.password = await this.hashingService.hash(signUpDto.password);

      await this.userRepository.save(user);
    } catch (err) {
      const pgUniqueViolationErrorCode = '23505';
      if (err.code === pgUniqueViolationErrorCode)
        throw new ConflictException();

      throw err;
    }
  }

  async signIn(signInDto: SignInDto) {
    const user = await this.userRepository.findOneBy({
      email: signInDto.email,
    });

    if (!user) throw new UnauthorizedException('User does not exists');

    const isEqual = await this.hashingService.compare(
      signInDto.password,
      user.password,
    );

    if (!isEqual) throw new UnauthorizedException('Password does not match');

    return this.generateTokens(user);
  }

  async generateTokens(user: User) {
    const [accessToken, refreshToken] = await Promise.all([
      this.signToken<Partial<ActiveUserData>>(
        user.id,
        this.jwtConfig.accessTokenTtl,
        { email: user.email },
      ),
      this.signToken(user.id, this.jwtConfig.refreshTokenTtl),
    ]);

    return {
      accessToken,
      refreshToken,
    };
  }

  async refreshTokens(refreshToken: RefreshTokenDto) {
    try {
      const { sub } = await this.jwtService.verifyAsync<
        Pick<ActiveUserData, 'sub'>
      >(refreshToken.refreshToken, {
        secret: this.jwtConfig.secret,
        audience: this.jwtConfig.audience,
        issuer: this.jwtConfig.issuer,
      });

      const user = await this.userRepository.findOneByOrFail({
        id: sub,
      });

      return this.generateTokens(user);
    } catch (_) {
      throw new UnauthorizedException();
    }
  }

  private async signToken<T>(userId: number, expiresIn: number, payload?: T) {
    return await this.jwtService.signAsync(
      {
        sub: userId,
        ...payload,
      },
      {
        audience: this.jwtConfig.audience,
        issuer: this.jwtConfig.issuer,
        secret: this.jwtConfig.secret,
        expiresIn,
      },
    );
  }
}
