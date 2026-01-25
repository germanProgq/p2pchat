/**
 * @format
 */

import React from 'react';
import ReactTestRenderer from 'react-test-renderer';
import App from '../App';

jest.mock('react-native-fs', () => ({
  DocumentDirectoryPath: '/tmp',
  exists: jest.fn(async () => true),
  mkdir: jest.fn(async () => undefined),
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
    connectPeer: jest.fn(),
    send: jest.fn(),
    getHistory: jest.fn(() => []),
    linkDevice: jest.fn(),
    onMessage: jest.fn(() => ({remove: jest.fn()})),
    onConnectionChange: jest.fn(() => ({remove: jest.fn()})),
    onPeerStatus: jest.fn(() => ({remove: jest.fn()})),
    onError: jest.fn(() => ({remove: jest.fn()}))
  }
}));

test('renders correctly', async () => {
  await ReactTestRenderer.act(() => {
    ReactTestRenderer.create(<App />);
  });
});
