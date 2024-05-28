import {
  Column,
  Entity,
  JoinTable,
  OneToMany,
  PrimaryGeneratedColumn,
} from 'typeorm';
import { Role } from '../enums/role.enum';
import {
  Permission,
  PermissionType,
} from '../../iam/authorization/permission.type';
import { ApiKey } from '../api-keys/entities/api-keys.entity/api-keys.entity';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true })
  password?: string;

  @Column({ enum: Role, default: Role.Regular })
  role: Role;

  // NOTE: Having the "permission" column in the combination with the "role"
  // likely does not make sense. We use both in this course just to showcase
  // two different approach to authorization.
  // It can make more sense to merge it with the "Role" to add more specification to roles...
  @Column({ enum: Permission, default: [], type: 'json' })
  permissions: PermissionType[];

  @Column({ default: false })
  isTfaEnabled: boolean;

  @Column({ nullable: true })
  tfaSecret: string;

  @JoinTable()
  @OneToMany(() => ApiKey, (apiKey) => apiKey.user)
  apiKeys: ApiKey[];

  @Column({ nullable: true })
  googleId?: string;
}
