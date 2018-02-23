import { get } from 'lodash';
import logger from 'winston';

const permissionDelim = ':';
const projectName = 'project';

function permissionWrapper(permissionSuffix) {
  const requiredPermission = projectName.concat(permissionDelim, permissionSuffix);

  return (request, response, next) => {
    const grantedPermissions = get(request, 'user.permissions') || [];

    logger.info('Auth: checking permissions');
    logger.debug(`Auth: expected permission suffix: ${permissionSuffix}`);
    logger.debug(`Auth: expected permission: ${requiredPermission}`);
    logger.debug(`Auth: granted user permissions: ${grantedPermissions}`);

    if (grantedPermissions.includes(requiredPermission)) {
      logger.info('Auth: permission check: PASSED');
      next();
    } else {
      logger.warn('Auth: permission check: FAILED');
      response.status(401)
        .send({ message: `User missing expected permission: ${requiredPermission}` })
        .end();
    }
  };
}

export default permissionWrapper;
