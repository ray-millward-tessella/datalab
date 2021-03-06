import axios from 'axios';
import logger from 'winston';
import config from '../../config';

const vaultBaseUrl = config.get('vaultApi');
const vaultAppRole = config.get('vaultAppRole');

function requestStorageKeys(projectKey, storage) {
  const keyPath = `${projectKey}/storage/${storage.name}`;
  return requestPath(keyPath);
}

function requestStackKeys(projectKey, stack) {
  const keyPath = `${projectKey}/stacks/${stack.name}`;
  return requestPath(keyPath);
}

function requestPath(path) {
  logger.info('Requesting vault secrets from path: %s', path);
  return requestVaultToken()
    .then(requestSecret(path))
    .then(response => response.data.data)
    .catch((error) => {
      logger.error('Error retrieving secret %s: ', path, error.response.data);
      return { message: 'Unable to retrieve secret' };
    });
}

function requestVaultToken() {
  if (!vaultAppRole) {
    logger.error('VAULT_APP_ROLE has not been set. Vault authentication will fail!');
  }

  const data = {
    role_id: vaultAppRole,
  };

  return axios.post(getAppRoleLoginUrl(), data);
}

const requestSecret = path => (response) => {
  const params = {
    headers: { 'X-Vault-Token': response.data.auth.client_token },
  };

  return axios.get(getSecretUrl(path), params);
};

function getAppRoleLoginUrl() {
  logger.debug(`Vault login url: ${vaultBaseUrl}/v1/auth/approle/login`);
  return `${vaultBaseUrl}/v1/auth/approle/login`;
}

function getSecretUrl(path) {
  logger.debug(`Vault secret url: ${vaultBaseUrl}/v1/secret/${path}`);
  return `${vaultBaseUrl}/v1/secret/${path}`;
}

export default { requestPath, requestStorageKeys, requestStackKeys };
