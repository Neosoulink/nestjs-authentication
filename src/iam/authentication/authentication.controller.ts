import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Res,
} from '@nestjs/common';
import { Response } from 'express';

import { Auth } from './decorators/auth.decorator';
import { AuthType } from './enums/auth-type.enum';
import { AuthenticationService } from './authentication.service';
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';

@Auth(AuthType.none)
@Controller('authentication')
export class AuthenticationController {
  constructor(private readonly authService: AuthenticationService) {}

  @Post('sign-up')
  signUp(@Body() signUpDto: SignUpDto) {
    return this.authService.signUp(signUpDto);
  }

  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  async signIn(
    @Res({ passthrough: true }) res: Response,
    @Body() signInDto: SignInDto,
  ) {
    const accessToken = await this.authService.signIn(signInDto);

    res.cookie('accessToken', accessToken, {
      secure: true,
      httpOnly: true,
      sameSite: true,
    });

    return accessToken;
  }

  @HttpCode(HttpStatus.OK)
  @Post('refresh-token')
  async refresh(
    @Res({ passthrough: true }) res: Response,
    @Body() refreshToken: RefreshTokenDto,
  ) {
    const accessToken = await this.authService.refreshTokens(refreshToken);

    res.cookie('accessToken', accessToken, {
      secure: true,
      httpOnly: true,
      sameSite: true,
    });

    return accessToken;
  }
}
