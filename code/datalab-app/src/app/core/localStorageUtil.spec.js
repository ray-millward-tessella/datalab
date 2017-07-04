import LocalStorageMock from './LocalStorageMock';
import { addToLocalStorage, removeFromLocalStorage } from './localStorageUtil';

describe('localStorageUtil', () => {
  beforeEach(() => {
    global.localStorage = new LocalStorageMock();
  });

  it('addToLocalStorage stores values when given a known key name', () => {
    // Arrange
    const sessionValues = [
      ['access_token', 'one'],
      ['expires_at', 'two'],
      ['id_token', 'three'],
    ];

    // Act
    sessionValues.forEach(([key, value]) => addToLocalStorage(key, value));

    // Assert
    expect(localStorage.store.access_token).toBe('one');
    expect(localStorage.store.expires_at).toBe('two');
    expect(localStorage.store.id_token).toBe('three');
  });

  it('addToLocalStorage throws and error when using unknown field name', () => {
    // Act/Assert
    expect(() => addToLocalStorage('accessToken', 'value'))
      .toThrow('Unknown localStorage field name: accessToken.');

    expect(() => addToLocalStorage('expiresAt', 'value'))
      .toThrow('Unknown localStorage field name: expiresAt.');

    expect(() => addToLocalStorage('idToken', 'value'))
      .toThrow('Unknown localStorage field name: idToken.');
  });

  it('removeFromLocalStorage deletes entry for given key', () => {
    // Arrange
    localStorage.store = {
      access_token: 'one',
      expires_at: 'two',
      id_token: 'three',
    };

    // Act/Assert
    expect(localStorage.store.access_token).toBe('one');
    removeFromLocalStorage('access_token');
    expect(localStorage.store.access_token).toBe(undefined);

    expect(localStorage.store.expires_at).toBe('two');
    removeFromLocalStorage('expires_at');
    expect(localStorage.store.expires_at).toBe(undefined);

    expect(localStorage.store.id_token).toBe('three');
    removeFromLocalStorage('id_token');
    expect(localStorage.store.id_token).toBe(undefined);
  });
});
