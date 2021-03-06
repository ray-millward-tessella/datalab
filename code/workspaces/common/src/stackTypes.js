import { keyBy, capitalize } from 'lodash';

const JUPYTER = 'jupyter';
const JUPYTERLAB = 'jupyterlab';
const ZEPPELIN = 'zeppelin';
const RSTUDIO = 'rstudio';
const RSHINY = 'rshiny';
const NBVIEWER = 'nbviewer';
const NFS_VOLUME = 'nfs';
const PROJECT = 'project';

const ANALYSIS = 'analysis';
const PUBLISH = 'publish';
const DATA_STORE = 'dataStore';

const STACK_TYPES = [
  {
    name: JUPYTER,
    shortDescription: 'A Jupyter Notebook',
    category: ANALYSIS,
  },
  {
    name: JUPYTERLAB,
    shortDescription: 'A Jupyter Lab',
    category: ANALYSIS,
  },
  {
    name: RSTUDIO,
    shortDescription: 'An RStudio Server',
    category: ANALYSIS,
  },
  {
    name: ZEPPELIN,
    shortDescription: 'A Zeppelin Notebook',
    category: ANALYSIS,
  },
  {
    name: RSHINY,
    shortDescription: 'An RShiny Site',
    category: PUBLISH,
  },
  {
    name: NBVIEWER,
    shortDescription: 'An Jupyter Notebook Viewer Site',
    category: PUBLISH,
  },
  {
    name: NFS_VOLUME,
    shortDescription: 'A NFS volume',
    category: DATA_STORE,
  },
];

function getStackTypes() {
  const types = STACK_TYPES.map(type => ({ description: type.shortDescription, value: type.name }));
  return keyBy(types, type => type.value);
}

function getStackSelections(category) {
  return STACK_TYPES.filter(stack => stack.category === category)
    .map(stack => ({ text: capitalize(stack.name), value: stack.name }));
}

function getStackKeys() {
  return STACK_TYPES.map(type => type.name);
}

export {
  ANALYSIS,
  DATA_STORE,
  JUPYTER,
  JUPYTERLAB,
  NBVIEWER,
  NFS_VOLUME,
  PROJECT,
  PUBLISH,
  RSHINY,
  RSTUDIO,
  ZEPPELIN,
  getStackKeys,
  getStackSelections,
  getStackTypes,
};
