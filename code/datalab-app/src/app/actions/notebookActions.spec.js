import notebookActions, {
  LOAD_NOTEBOOKS_ACTION,
  GET_NOTEBOOK_URL_ACTION,
  OPEN_NOTEBOOK_ACTION,
} from './notebookActions';
import notebookService from '../api/notebookService';

jest.mock('../api/notebookService');

describe('notebookActions', () => {
  beforeEach(() => jest.resetAllMocks());

  describe('calls correct service for', () => {
    it('loadNotebooks', () => {
      // Arrange
      const loadNotebooksMock = jest.fn().mockReturnValue('expectedNotebooksPayload');
      notebookService.loadNotebooks = loadNotebooksMock;

      // Act
      const output = notebookActions.loadNotebooks();

      // Assert
      expect(loadNotebooksMock).toHaveBeenCalledTimes(1);
      expect(output.type).toBe('LOAD_NOTEBOOKS');
      expect(output.payload).toBe('expectedNotebooksPayload');
    });

    it('getUrl', () => {
      // Arrange
      const getUrlMock = jest.fn().mockReturnValue('expectedUrlPayload');
      notebookService.getUrl = getUrlMock;

      // Act
      const output = notebookActions.getUrl();

      // Assert
      expect(getUrlMock).toHaveBeenCalledTimes(1);
      expect(output.type).toBe('GET_NOTEBOOK_URL');
      expect(output.payload).toBe('expectedUrlPayload');
    });

    it('openNotebook', () => {
      // Arrange
      global.open = jest.fn();

      // Act
      notebookActions.openNotebook('url');

      // Assert
      expect(global.open).toBeCalledWith('url');
    });
  });

  describe('exports correct values for', () => {
    it('LOAD_NOTEBOOKS_ACTION', () => {
      expect(LOAD_NOTEBOOKS_ACTION).toBe('LOAD_NOTEBOOKS');
    });

    it('GET_NOTEBOOK_URL_ACTION', () => {
      expect(GET_NOTEBOOK_URL_ACTION).toBe('GET_NOTEBOOK_URL');
    });

    it('OPEN_NOTEBOOK_ACTION', () => {
      expect(OPEN_NOTEBOOK_ACTION).toBe('OPEN_NOTEBOOK');
    });
  });
});