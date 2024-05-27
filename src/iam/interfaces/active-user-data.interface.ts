import { Role } from '../../users/enums/role.enum';

export interface ActiveUserData {
  /**
   * The "subject" of the token. the value of this property is the user ID
   * that granted this token.
   */
  sub: number;

  /**
   * The subject's (user) email.
   */
  email: string;

  /**
   * Subject's (user) role.
   */
  role: Role;
}
