import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { promisify } from 'util';
import { Request } from 'express';

import { Auth } from './decorators/auth.decorator';
import { ActiveUser } from '../decorators/active-user.decorator';
import { AuthType } from './enums/auth-type.enum';
import { SessionAuthenticationService } from './session-authentication.service';
import { SignInDto } from './dto/sign-in.dto';
import { SessionGuard } from './guards/session/session.guard';
import { ActiveUserData } from '../interfaces/active-user-data.interface';

@Auth(AuthType.None)
@Controller('session-authentication')
export class SessionAuthenticationController {
  constructor(
    private readonly sessionAuthService: SessionAuthenticationService,
  ) {}

  @HttpCode(HttpStatus.OK)
  @Post('sign-in')
  async signIn(@Req() req: Request, @Body() signInDto: SignInDto) {
    const user = await this.sessionAuthService.signIn(signInDto);

    await promisify(req.logIn).call(req, user);
  }

  @UseGuards(SessionGuard)
  @Get()
  async sayHello(@ActiveUser() user: ActiveUserData) {
    return `Hello, ${user.email}!`;
  }
}
