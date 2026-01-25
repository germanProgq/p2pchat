// Mobile bridge wrapper for core module. Spec: app/bridge/BridgeSpec.md.
import {NativeEventEmitter, NativeModules} from 'react-native';
import type {BridgeSpec, HistoryMessage, IncomingMessage, NodeConfig} from 'p2pchat-bridge';
import {NativeBridge} from 'p2pchat-bridge';

const bridge = NativeModules.Bridge as BridgeSpec;
const emitter = new NativeEventEmitter(NativeBridge as any);

export type {HistoryMessage, IncomingMessage, NodeConfig};

export const Bridge = {
  start: (config: NodeConfig) => bridge.start(config),
  localBundle: () => bridge.localBundle(),
  localIce: () => bridge.localIce(),
  beginLink: () => bridge.beginLink(),
  addContact: (bundle: ArrayBuffer) => bridge.addContact(bundle),
  addContactWithUsername: (bundle: ArrayBuffer, username: string) => bridge.addContactWithUsername(bundle, username),
  connectPeer: (peerInfo: {peerId: string; address?: string; port?: number; iceBlob?: string}) => bridge.connectPeer(peerInfo),
  send: (chatId: string, payload: string | ArrayBuffer) => bridge.send(chatId, payload),
  getHistory: (chatId: string, cursor: number, limit: number) => bridge.getHistory(chatId, cursor, limit),
  linkDevice: (code: string) => bridge.linkDevice(code),
  localUsername: () => bridge.localUsername(),
  localIdentityPublicKey: () => bridge.localIdentityPublicKey(),
  signIdentity: (message: ArrayBuffer) => bridge.signIdentity(message),
  updateProfile: (username: string, password: string) => bridge.updateProfile(username, password),
  onMessage: (handler: (msg: IncomingMessage) => void) => emitter.addListener('onMessage', handler),
  onConnectionChange: (handler: (event: any) => void) => emitter.addListener('onConnectionChange', handler),
  onPeerStatus: (handler: (event: any) => void) => emitter.addListener('onPeerStatus', handler),
  onError: (handler: (event: any) => void) => emitter.addListener('onError', handler)
};
