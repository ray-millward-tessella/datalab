import { blue, green, yellow } from 'material-ui/colors';
import { keyBy, capitalize } from 'lodash';

export const REQUESTED = 'requested';
export const CREATING = 'creating';
export const READY = 'ready';
export const UNAVAILABLE = 'unavailable';

const STATUS_TYPES = [
  {
    name: REQUESTED,
    description: 'Resource has been requested',
    color: blue[100],
    invertColor: true,
  },
  {
    name: CREATING,
    description: 'Resource is being created',
    color: blue[500],
  },
  {
    name: READY,
    description: 'Resource is ready for use',
    color: green[500],
  },
  {
    name: UNAVAILABLE,
    description: 'Resource is currently unavailable',
    color: yellow[600],
    invertColor: true,
  },
];

function getStatusTypes() {
  const types = STATUS_TYPES.map(({ name, description, color, invertColor }) => ({
    description,
    color,
    invertColor,
    displayName: capitalize(name),
    value: name,
  }));
  return keyBy(types, type => type.value);
}

function getStatusKeys() {
  return STATUS_TYPES.map(type => type.name);
}

function getStatusProps(status) {
  return getStatusTypes()[status];
}

export { getStatusTypes, getStatusKeys, getStatusProps };