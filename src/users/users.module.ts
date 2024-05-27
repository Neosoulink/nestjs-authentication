import { Module } from '@nestjs/common';
import { UsersService } from './users.service';
import { UsersController } from './users.controller';
import { TypeOrmModule } from '@nestjs/typeorm';

import { ApiKey } from './api-keys/entities/api-keys.entity/api-keys.entity';
import { User } from './entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User, ApiKey])],
  controllers: [UsersController],
  providers: [UsersService],
})
export class UsersModule {}
