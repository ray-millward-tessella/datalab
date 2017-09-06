import notebookRepository from './notebookRepository';
import database from '../config/database';
import databaseMock from './testUtil/databaseMock';

jest.mock('../config/database');

const testNotebooks = [
  { name: 'Notebook 1' },
  { name: 'Notebook 2' },
];
const mockDatabase = databaseMock(testNotebooks);
database.getModel = mockDatabase;

describe('notebookRepository', () => {
  beforeEach(() => {
    mockDatabase().clearQuery();
  });

  it('getAll returns expected snapshot', () =>
    notebookRepository.getAll('user').then((notebooks) => {
      expect(mockDatabase().query()).toEqual({});
      expect(notebooks).toMatchSnapshot();
    }));

  it('getById returns expected snapshot', () =>
    notebookRepository.getById(undefined, '599aa983bdd5430daedc8eec').then((notebook) => {
      expect(mockDatabase().query()).toEqual({ _id: '599aa983bdd5430daedc8eec' });
      expect(notebook).toMatchSnapshot();
    }));
});