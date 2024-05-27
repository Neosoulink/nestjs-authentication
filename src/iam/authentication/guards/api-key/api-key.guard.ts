import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Request } from 'express';

import { ApiKeysService } from '../../api-keys.service';
import { ApiKey } from '../../../../users/api-keys/entities/api-keys.entity/api-keys.entity';
import { REQUEST_USER_KEY } from 'src/iam/iam.constants';
import { ActiveUserData } from 'src/iam/interfaces/active-user-data.interface';

@Injectable()
export class ApiKeyGuard implements CanActivate {
  constructor(
    private readonly apiKeysService: ApiKeysService,
    @InjectRepository(ApiKey)
    private readonly apiKeysRepository: Repository<ApiKey>,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const apiKey = this.extractFromHeader(request);

    if (!apiKey) throw new UnauthorizedException();

    const apiKeyEntityId = this.apiKeysService.extractIdFromApiKey(apiKey);

    try {
      const apiKeyEntity = await this.apiKeysRepository.findOne({
        where: { uuid: apiKeyEntityId },
        relations: { user: true },
      });
      await this.apiKeysService.validate(apiKey, apiKeyEntity.key);
      request[REQUEST_USER_KEY] = {
        sub: apiKeyEntity.user.id,
        email: apiKeyEntity.user.email,
        role: apiKeyEntity.user.role,
        permissions: apiKeyEntity.user.permissions,
      } satisfies ActiveUserData;
    } catch (error) {}

    return true;
  }

  private extractFromHeader(request: Request): string | undefined {
    const [type, key] = request.headers.authorization?.split(' ') ?? [];

    return type === 'ApiKey' ? key : undefined;
  }
}
