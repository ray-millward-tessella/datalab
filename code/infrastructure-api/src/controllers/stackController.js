import { check } from 'express-validator/check';
import { matchedData, sanitize } from 'express-validator/filter';
import controllerHelper from './controllerHelper';
import stackManager from '../stacks/stackManager';

const TYPE = 'stack';

function createStack(request, response) {
  const errorMessage = 'Invalid stack creation request';
  return controllerHelper.validateAndExecute(request, response, errorMessage, createStackExec);
}

function deleteStack(request, response) {
  const errorMessage = 'Invalid stack deletion request';
  return controllerHelper.validateAndExecute(request, response, errorMessage, deleteStackExec);
}

function createStackExec(request, response) {
  // Build request params
  const { datalabInfo, name, type } = matchedData(request);

  // Handle request
  return stackManager.createStack(datalabInfo, name, type)
    .then(controllerHelper.sendSuccessfulCreation(response))
    .catch(controllerHelper.handleError(response, 'creating', TYPE, name));
}

function deleteStackExec(request, response) {
  // Build request params
  const { datalabInfo, name, type } = matchedData(request);

  // Handle request
  return stackManager.deleteStack(datalabInfo, name, type)
    .then(controllerHelper.sendSuccessfulDeletion(response))
    .catch(controllerHelper.handleError(response, 'deleting', TYPE, name));
}

const createStackValidator = [
  sanitize('*').trim(),
  check('datalabInfo.name').exists().withMessage('datalabInfo.name must be specified'),
  check('datalabInfo.domain').exists().withMessage('datalabInfo.domain must be specified'),
  check('datalabInfo.volume').exists().withMessage('datalabInfo.volume must be specified'),
  check('name')
    .exists()
    .withMessage('Name must be specified')
    .isAscii()
    .withMessage('Name must only use the characters a-z')
    .isLength({ min: 4, max: 12 })
    .withMessage('Name must be 4-12 characters long'),
  check('type').exists().withMessage('Type must be specified'),
];

export default { createStackValidator, createStack, deleteStack };