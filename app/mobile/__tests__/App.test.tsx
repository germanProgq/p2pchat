/**
 * @format
 */

import React from 'react';
import ReactTestRenderer from 'react-test-renderer';
import App from '../App';

const dispatchEvent = jest.fn();

Object.defineProperty(globalThis, 'window', {
  value: {...(globalThis as any).window, dispatchEvent},
  writable: true
});

jest.mock('react-native-fs', () => ({
  DocumentDirectoryPath: '/tmp',
  exists: jest.fn(async () => false),
  mkdir: jest.fn(async () => undefined),
  readFile: jest.fn(async () => '{}'),
  writeFile: jest.fn(async () => undefined)
}), {virtual: true});

jest.mock('@react-native-clipboard/clipboard', () => ({
  setString: jest.fn()
}), {virtual: true});

jest.mock('../src/bridge', () => ({
  Bridge: {
    start: jest.fn(),
    localBundle: jest.fn(() => new ArrayBuffer(0)),
    localIce: jest.fn(() => ''),
    beginLink: jest.fn(() => ''),
    addContact: jest.fn(() => 'peer'),
    addContactWithUsername: jest.fn(() => 'peer'),
    connectPeer: jest.fn(),
    send: jest.fn(),
    getHistory: jest.fn(() => []),
    linkDevice: jest.fn(),
    localUsername: jest.fn(() => 'tester'),
    localIdentityPublicKey: jest.fn(() => new ArrayBuffer(32)),
    signIdentity: jest.fn(() => new ArrayBuffer(64)),
    updateProfile: jest.fn(),
    onMessage: jest.fn(() => ({remove: jest.fn()})),
    onConnectionChange: jest.fn(() => ({remove: jest.fn()})),
    onPeerStatus: jest.fn(() => ({remove: jest.fn()})),
    onError: jest.fn(() => ({remove: jest.fn()}))
  }
}));

test('renders correctly', async () => {
  let renderer: ReactTestRenderer.ReactTestRenderer | undefined;
  await ReactTestRenderer.act(async () => {
    renderer = ReactTestRenderer.create(<App />);
    await Promise.resolve();
  });
  await ReactTestRenderer.act(async () => {
    renderer?.unmount();
    await Promise.resolve();
  });
});
