import React from 'react';
import { shallow } from 'enzyme';
import { PureCreateNotebookForm } from './CreateNotebookForm';

describe('CreateNotebookForm', () => {
  function shallowRender(props) {
    return shallow(<PureCreateNotebookForm {...props} />);
  }

  const onSubmitMock = jest.fn();
  const onCancelMock = jest.fn();

  const generateProps = () => ({
    onSubmit: onSubmitMock,
    cancel: onCancelMock,
    dataStorageOptions: [
      { text: 'First Data Store', value: 'alpha' },
      { text: 'Second Data Store', value: 'beta' },
    ],
    projectKey: 'testproj',
  });

  beforeEach(() => jest.resetAllMocks());

  it('creates correct snapshot for create Notebook Form', () => {
    // Arrange
    const props = generateProps();

    // Act
    const output = shallowRender(props);

    // Assert
    expect(output).toMatchSnapshot();
  });
});
