import React from 'react';
import { shallow } from 'enzyme';
import CreateSiteDialog from './CreateSiteDialog';

describe('Site dialog', () => {
  function shallowRender(props) {
    return shallow(<CreateSiteDialog {...props} />);
  }

  const onSubmitMock = jest.fn();
  const onCancelMock = jest.fn();

  const generateProps = () => ({
    title: 'Title',
    onSubmit: onSubmitMock,
    onCancel: onCancelMock,
    dataStorageOptions: [
      { value: 'value' },
      { value: 'another value' },
    ],
  });

  beforeEach(() => jest.resetAllMocks());

  it('creates correct snapshot', () => {
    // Arrange
    const props = generateProps();

    // Act
    const output = shallowRender(props);

    // Assert
    expect(output).toMatchSnapshot();
  });

  it('wires up cancel function correctly', () => {
    // Arrange
    const props = generateProps();

    // Act
    const output = shallowRender(props);
    const cancelFunction = output.find('ReduxForm').prop('cancel');
    cancelFunction();

    // Assert
    expect(onCancelMock).toHaveBeenCalled();
  });

  it('wires up submit function correctly', () => {
    // Arrange
    const props = generateProps();

    // Act
    const output = shallowRender(props);
    const submitFunction = output.find('ReduxForm').prop('onSubmit');
    submitFunction();

    // Assert
    expect(onSubmitMock).toHaveBeenCalled();
  });
});
