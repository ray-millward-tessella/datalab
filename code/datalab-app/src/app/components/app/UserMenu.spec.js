import React from 'react';
import { createShallow } from 'material-ui/test-utils';
import UserMenu from './UserMenu';
import auth from '../../auth/auth';

const closePopoverMock = jest.fn();

const expectedProps = {
  identity: {
    name: 'expectedName',
    nickname: 'expectedNickname',
    picture: 'expectedPicture',
  },
  closePopover: closePopoverMock,
};

describe('UserMenu', () => {
  beforeEach(() => {
    jest.resetAllMocks();
  });

  function shallowRender(props) {
    const shallow = createShallow({ dive: true });

    return shallow(<UserMenu {...props} />);
  }

  it('renders correct snapshot', () => {
    expect(shallowRender(expectedProps)).toMatchSnapshot();
  });

  it('wraps auth.logout with closePopover wrapper', () => {
    expect(closePopoverMock).not.toHaveBeenCalled();

    shallowRender(expectedProps);

    expect(closePopoverMock).toHaveBeenCalledWith(auth.logout);
  });
});