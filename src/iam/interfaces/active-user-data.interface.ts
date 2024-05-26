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
}
