import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';

import jwtConfig from '../config/jwt.config';
import { User } from '../users/entities/user.entity';
import { ApiKey } from '../users/api-keys/entities/api-keys.entity/api-keys.entity';
import { AuthenticationService } from './authentication/authentication.service';
import { HashingService } from './hashing/hashing.service';
import { BcryptService } from './hashing/bcrypt.service';
import { AuthenticationController } from './authentication/authentication.controller';
import { AccessTokenGuard } from './authentication/guards/access-token/access-token.guard';
import { AuthenticationGuard } from './authentication/guards/authentication/authentication.guard';
import { RolesGuard } from './authorization/guards/roles/roles.guard';
import { PermissionsGuard } from './authorization/guards/permissions/permissions.guard';
import { PoliciesGuard } from './authorization/guards/policies/policies.guard';
import { RefreshTokenIdsStorage } from './authentication/refresh-token-ids.storage';
import { PolicyHandlerStorage } from './authorization/policies/policy-handler.storage';
import { FrameworkContributorPolicyHandler } from './authorization/policies/framework-contributor.policy';
import { ApiKeysService } from './authentication/api-keys.service';
import { ApiKeyGuard } from './authentication/guards/api-key/api-key.guard';

@Module({
  imports: [
    TypeOrmModule.forFeature([User, ApiKey]),
    JwtModule.registerAsync(jwtConfig.asProvider()),
    ConfigModule.forFeature(jwtConfig),
  ],
  providers: [
    { provide: HashingService, useClass: BcryptService },
    { provide: APP_GUARD, useClass: AuthenticationGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
    { provide: APP_GUARD, useClass: PoliciesGuard },
    AccessTokenGuard,
    ApiKeyGuard,
    RefreshTokenIdsStorage,
    AuthenticationService,
    PolicyHandlerStorage,
    FrameworkContributorPolicyHandler,
    ApiKeysService,
  ],
  controllers: [AuthenticationController],
})
export class IamModule {}
