import validate from 'validate.js';
import dataStorageActions from '../../actions/dataStorageActions';
import { getStackKeys } from '../../../shared/stackTypes';

const constraints = {
  displayName: {
    presence: true,
  },
  type: {
    presence: true,
    inclusion: getStackKeys(),
  },
  volumeSize: {
    presence: true,
    numericality: {
      onlyInteger: true,
      greaterThanOrEqualTo: 5,
      lessThanOrEqualTo: 200,
    },
  },
  name: {
    presence: true,
    format: {
      pattern: '^[a-z]*$',
      message: 'must be lower case characters without a space',
    },
    length: {
      minimum: 4,
      maximum: 12,
    },
  },
  description: {
    presence: true,
  },
};

validate.formatters.reduxForm = error => error.reduce(errorReducer, {});

function errorReducer(accumulator, error) {
  accumulator[error.attribute] = error.error; // eslint-disable-line no-param-reassign
  return accumulator;
}

export const syncValidate = values => validate(values, constraints, { format: 'reduxForm' });

export const asyncValidate = (values, dispatch) =>
  dispatch(dataStorageActions.checkDataStoreName(values.name))
    .then((response) => {
      if (response.value) {
        return Promise.reject({ name: 'Data Store already exists. Name must be unique' });
      }
      return Promise.resolve();
    });