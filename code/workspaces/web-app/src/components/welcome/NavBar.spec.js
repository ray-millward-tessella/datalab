import React from 'react';
import { createShallow } from '@material-ui/core/test-utils';
import NavBar from './NavBar';
import getAuth from '../../auth/auth';

jest.mock('../../auth/auth');
getAuth.mockImplementation(() => ({
  login: jest.fn(),
}));

describe('NavBar', () => {
  let shallow;

  beforeEach(() => {
    shallow = createShallow({ dive: true });
  });

  it('renders correct snapshot', () => {
    expect(shallow(<NavBar />)).toMatchSnapshot();
  });
});
