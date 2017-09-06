import axios from 'axios';
import logger from 'winston';
import has from 'lodash/has';
import config from '../config/config';

const vaultBaseUrl = config.get('vaultApi');
const vaultAppRole = config.get('vaultAppRole');

function storeSecret(path, value) {
  logger.info('Storing secrets in vault path: %s', path);
  return requestVaultToken()
    .then(storeVaultSecret(path, value))
    .catch(handleError(path));
}

const storeVaultSecret = (path, value) => (response) => {
  const params = {
    headers: { 'X-Vault-Token': response.data.auth.client_token },
  };

  return axios.post(getSecretUrl(path), value, params);
};

function requestVaultToken() {
  if (!vaultAppRole) {
    logger.error('VAULT_APP_ROLE has not been set. Vault authentication will fail!');
  }

  const data = {
    role_id: vaultAppRole,
  };

  return axios.post(getAppRoleLoginUrl(), data);
}

function getAppRoleLoginUrl() {
  logger.debug(`Vault login url: ${vaultBaseUrl}/v1/auth/approle/login`);
  return `${vaultBaseUrl}/v1/auth/approle/login`;
}

function getSecretUrl(path) {
  logger.debug(`Vault secret url: ${vaultBaseUrl}/v1/secret/${path}`);
  return `${vaultBaseUrl}/v1/secret/${path}`;
}

const handleError = path => (error) => {
  if (has(error, 'response.data')) {
    logger.error('Error retrieving secret %s: ', path, error.response.data);
  } else {
    logger.error('Error retrieving secret %s: ', path, error);
  }
  return { message: 'Unable to retrieve secret' };
};

export default { storeSecret };