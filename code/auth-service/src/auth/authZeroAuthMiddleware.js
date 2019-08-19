import jwt from 'express-jwt';
import jwksRsa from 'jwks-rsa';

const secretStrategy = jwksRsa.expressJwtSecret({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
  jwksUri: 'http://keycloak:8080/auth/realms/DataLabs/protocol/openid-connect/certs',
});

const baseConfig = {
  secret: secretStrategy,
  audience: 'account',
  issuer: 'http://keycloak:8080/auth/realms/DataLabs',
  algorithms: ['RS256'],
};

export const cookieAuthMiddleware = jwt({
  ...baseConfig,
  getToken: request => request.cookies.authorization,
});

export const tokenAuthMiddleware = jwt(baseConfig);
