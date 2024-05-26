import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

import { AuthenticationService } from './authentication/authentication.service';
import { HashingService } from './hashing/hashing.service';
import { BcryptService } from './hashing/bcrypt.service';

import { User } from '../users/entities/user.entity';
import { AuthenticationController } from './authentication/authentication.controller';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [
    { provide: HashingService, useClass: BcryptService },
    AuthenticationService,
  ],
  controllers: [AuthenticationController],
})
export class IamModule {}
