import axios from 'axios';
import logger from '../config/logger';
import config from '../config/config';
import { handleCreateError, handleDeleteError } from './core';

const API_BASE = config.get('kubernetesApi');
const NAMESPACE = config.get('podNamespace');

const SECRET_URL = `${API_BASE}/api/v1/namespaces/${NAMESPACE}/secrets`;

function createOrUpdateSecret(name, value) {
  return getSecret(name)
    .then(createOrReplace(name, value));
}

const createOrReplace = (name, value) => (existingSecret) => {
  if (existingSecret) {
    return updateSecret(name, value);
  }

  return createSecret(name, value);
};

function getSecret(name) {
  return axios.get(`${SECRET_URL}/${name}`)
    .then(response => response.data)
    .catch(() => undefined);
}

function createSecret(name, value) {
  logger.info('Creating secret: %s', name);
  return axios.post(SECRET_URL, createPayload(name, value))
    .catch(handleCreateError('secret', name));
}

function updateSecret(name, value) {
  logger.info('Updating secret: %s', name);
  return axios.put(`${SECRET_URL}/${name}`, createPayload(name, value))
    .catch(handleCreateError('secret', name));
}

function createPayload(name, value) {
  return {
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: { name },
    stringData: value,
  };
}

function deleteSecret(name) {
  logger.info('Deleting secret: %s', name);
  return axios.delete(`${SECRET_URL}/${name}`)
    .then(response => response.data)
    .catch(handleDeleteError('secret', name));
}

export default { getSecret, deleteSecret, createSecret, updateSecret, createOrUpdateSecret };