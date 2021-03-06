import React from 'react';
import { createShallow } from '@material-ui/core/test-utils';
import WelcomePage from './WelcomePage';

describe('WelcomePage', () => {
  let shallow;

  beforeEach(() => {
    shallow = createShallow({ dive: true });
  });

  it('renders correct snapshot', () => {
    expect(shallow(<WelcomePage />)).toMatchSnapshot();
  });
});
