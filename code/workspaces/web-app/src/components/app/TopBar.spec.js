import React from 'react';
import { createShallow } from '@material-ui/core/test-utils';
import TopBar from './TopBar';

describe('Topbar', () => {
  let shallow;

  beforeEach(() => {
    shallow = createShallow({ dive: true });
  });

  it('correctly renders correct snapshot', () => {
    expect(
      shallow(<TopBar identity={{ expected: 'identity', picture: 'expectedUrl' }} />),
    ).toMatchSnapshot();
  });
});
