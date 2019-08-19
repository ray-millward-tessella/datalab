import moment from 'moment';
import Promise from 'bluebird';
import jwt from 'jsonwebtoken';
import Keycloak from 'keycloak-js';
import { pick } from 'lodash';
import cookies from './cookies';
import { setSession, clearSession, getSession } from '../core/sessionUtil';
import loginScreens from './auth0UniversalLoginScreens';

class Auth {
  constructor(authInit, promisifyAuthInit) {
    // this.authConfig = authConfig;
    this.authInitAsync = promisifyAuthInit;
    this.authInit = authInit;
    this.login = this.login.bind(this);
    this.signUp = this.signUp.bind(this);
    this.logout = this.logout.bind(this);
    this.handleAuthentication = this.handleAuthentication.bind(this);
    this.renewSession = this.renewSession.bind(this);
    this.expiresIn = this.expiresIn.bind(this);
    this.isAuthenticated = this.isAuthenticated.bind(this);
    this.getCurrentSession = this.getCurrentSession.bind(this);
    this.redirectTo = '';
  }

  login() {
    // User redirected to Keycloak login page
    this.redirectTo = window.location.pathname;
    this.authInit.login({ redirectUri: 'https://testlab.datalabs.localhost/callback' });
  }

  signUp() {
    // Auth0 universal login configured to open on Sign Up page
    // Note: This required customization of Auth0 Universal Login widget (see auth0)
    const state = JSON.stringify({ appRedirect: window.location.pathname });
    this.authZeroInit.authorize({ state, initial_screen: loginScreens.SIGN_UP });
  }

  logout() {
    // User redirected to home page on logout
    clearSession();
    cookies.clearAccessToken();
    this.authInit.logout({ redirectUri: 'https://testlab.datalabs.localhost' });
  }

  parseHashParams(str) {
    return JSON.parse(`{"${decodeURI(str.replace(/#/, '')).replace(/"/g, '\\"').replace(/&/g, '","').replace(/=/g, '":"')}"}`);
  }

  handleAuthentication(callback) {
    return Promise.resolve(processHash(this.parseHashParams(callback), this.redirectTo));
  }

  renewSession() {
    return Promise.resolve(this.login());
  }

  expiresIn(expiresAt) {
    const expiresAtMoment = moment(expiresAt, 'x');
    if (!expiresAtMoment.isValid()) {
      throw new Error('Auth token expiresAt value is invalid.');
    }
    return expiresAtMoment.diff(moment.utc());
  }

  isAuthenticated(session) {
    if (session && session.expiresAt) {
      return this.expiresIn(session.expiresAt) > 0;
    }
    return false;
  }

  getCurrentSession() {
    const currentSession = getSession();
    return currentSession && processResponse(currentSession);
  }
}

function processHash(authResponse, redirectTo) {
  if (authResponse && authResponse.access_token && authResponse.id_token) {
    const unpackedResponse = processResponse(authResponse, redirectTo);
    cookies.storeAccessToken(unpackedResponse);
    setSession(unpackedResponse);
    return unpackedResponse;
  }
  return null;
}

function processResponse(authResponse, redirectTo) {
  const idTokenPayload = jwt.decode(authResponse.id_token);
  const state = processState(authResponse.state);
  const appRedirect = redirectTo;
  const expiresAt = authResponse.expiresAt || expiresAtCalculator(authResponse.expiresIn);
  const identity = authResponse.identity || processIdentity(idTokenPayload);

  return {
    ...authResponse,
    appRedirect,
    expiresAt,
    state,
    identity,
  };
}

function processState(state) {
  // auth0 silent renewal uses state parameter for a nonce value
  if (/appRedirect/.test(state)) {
    return JSON.parse(state);
  }
  return undefined;
}

function expiresAtCalculator(expiresIn) {
  return moment.utc().add(expiresIn, 's').format('x');
}

function processIdentity(idTokenPayload) {
  const knownFields = ['sub', 'name', 'nickname', 'picture'];

  return JSON.stringify(pick(idTokenPayload, knownFields));
}

let authSession;

const initialiseAuth = (authConfig) => {
  if (!authSession) {
    const keycloak = Keycloak('https://testlab.datalabs.localhost/keycloak.json');
    const PromisifyKeyCloak = Promise.promisifyAll(keycloak);
    keycloak.init({ flow: 'implicit' });
    authSession = new Auth(keycloak, PromisifyKeyCloak);
  }
};

const getAuth = () => (authSession);

export default getAuth;
export { initialiseAuth, Auth as PureAuth };
