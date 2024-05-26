import { registerAs } from '@nestjs/config';

export const config = () => ({
  secret: process.env.JWT_SECRET,
  audience: process.env.JWT_TOKEN_AUDIENCE,
  issuer: process.env.JWT_TOKEN_ISSUER,
  accessTokenTtl: parseInt(process.env.JWT_ACCESS_TOKEN_TTL ?? '3600', 10),
  refreshTokenTtl: parseInt(process.env.JWT_ACCESS_TOKEN_TTL ?? '86400', 10),
});
export const JWT_CONFIG_KEY = 'jwt';
export default registerAs(JWT_CONFIG_KEY, config);
