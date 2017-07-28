import React from 'react';
import { shallow } from 'enzyme';
import createStore from 'redux-mock-store';
import NotebooksContainer, { PureNotebooksContainer } from './NotebooksContainer';
import notebookService from '../../api/notebookService';

jest.mock('../../api/notebookService');
const loadNotebooksMock = jest.fn().mockReturnValue('expectedPayload');
notebookService.loadNotebooks = loadNotebooksMock;

describe('NotebooksContainer', () => {
  describe('is a connected component which', () => {
    function shallowRenderConnected(store) {
      const props = {
        store,
        PrivateComponent: () => {},
        PublicComponent: () => {},
      };

      return shallow(<NotebooksContainer {...props} />);
    }

    const notebooks = { fetching: false, value: ['expectedArray'] };

    it('extracts the correct props from the redux state', () => {
      // Arrange
      const store = createStore()({
        notebooks,
      });

      // Act
      const output = shallowRenderConnected(store);

      // Assert
      expect(output.prop('notebooks')).toBe(notebooks);
    });

    it('binds correct actions', () => {
      // Arrange
      const store = createStore()({
        notebooks,
      });

      // Act
      const output = shallowRenderConnected(store).prop('actions');

      // Assert
      expect(Object.keys(output)).toEqual(expect.arrayContaining(['loadNotebooks', 'openNotebook']));
    });

    it('loadNotebooks function dispatches correct action', () => {
      // Arrange
      const store = createStore()({
        notebooks,
      });

      // Act
      const output = shallowRenderConnected(store);

      // Assert
      expect(store.getActions().length).toBe(0);
      output.prop('actions').loadNotebooks();
      expect(store.getActions()[0]).toEqual({
        type: 'LOAD_NOTEBOOKS',
        payload: 'expectedPayload',
      });
    });
  });

  describe('is a container which', () => {
    function shallowRenderPure(props) {
      return shallow(<PureNotebooksContainer {...props} />);
    }

    const notebooks = { fetching: false, value: [{ props: 'value1' }, { props: 'value2' }] };

    const openNotebookFn = () => {};
    const generateProps = () => ({
      notebooks,
      actions: {
        loadNotebooks: loadNotebooksMock,
        openNotebook: openNotebookFn,
      },
    });

    beforeEach(() => jest.resetAllMocks());

    it('calls loadNotebooks action when mounted', () => {
      // Arrange
      const props = generateProps();

      // Act
      shallowRenderPure(props);

      // Assert
      expect(loadNotebooksMock).toHaveBeenCalledTimes(1);
    });

    it('passes correct props to NotebookButton', () => {
      // Arrange
      const props = generateProps();

      // Act
      expect(shallowRenderPure(props)).toMatchSnapshot();
    });
  });
});
