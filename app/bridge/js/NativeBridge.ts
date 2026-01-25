// RN TurboModule spec for Bridge. Spec: app/bridge/BridgeSpec.md.
import type {TurboModule} from 'react-native';
import {TurboModuleRegistry} from 'react-native';

export type ContentType = 'text' | 'binary';

export type IceCandidateType = 'host' | 'srflx' | 'relay';

export interface RelayCandidate {
  type: IceCandidateType;
  address: string;
  port: number;
  priority: number;
}

export interface IceConfig {
  stunServers?: string[];
  bindAddress?: string;
  bindPort?: number;
  timeoutMs?: number;
  relayCandidates?: RelayCandidate[];
}

export interface RetryPolicy {
  baseDelayMs?: number;
  maxDelayMs?: number;
  maxAttempts?: number;
  jitterRatio?: number;
}

export interface TransportConfig {
  maxInFlight?: number;
  maxQueueBytes?: number;
  retry?: RetryPolicy;
}

export interface QuicConfig {
  bindAddress?: string;
  bindPort?: number;
  maxDatagramSize?: number;
  ice?: IceConfig;
}

export interface WebRtcConfig {
  bindAddress?: string;
  bindPort?: number;
  maxDatagramSize?: number;
  ice?: IceConfig;
}

export interface NodeConfig {
  identityPath: string;
  storagePath: string;
  schemaPath: string;
  username?: string;
  password?: string;
  masterKey?: ArrayBuffer;
  transportKind?: 'quic' | 'webrtc' | 'loopback';
  transport?: TransportConfig;
  quic?: QuicConfig;
  webrtc?: WebRtcConfig;
  oneTimePrekeys?: number;
  signedPrekeyId?: number;
  oneTimeStartId?: number;
  handshakeBaseDelayMs?: number;
  handshakeMaxDelayMs?: number;
  handshakeMaxAttempts?: number;
}

export interface IncomingMessage {
  chatId: string;
  msgId: string;
  senderDevice: string;
  peerUsername: string;
  tsMs: number;
  contentType: ContentType;
  body: ArrayBuffer;
}

export interface HistoryMessage {
  chatId: string;
  msgId: string;
  senderDevice: string;
  peerUsername: string;
  tsMs: number;
  contentType: ContentType;
  body: ArrayBuffer;
  delivered: boolean;
  acked: boolean;
  index: number;
}

export interface BridgeSpec extends TurboModule {
  start(config: NodeConfig): void;
  localBundle(): ArrayBuffer;
  localIce(): string;
  beginLink(): string;
  addContact(prekeyBundle: ArrayBuffer): string;
  addContactWithUsername(prekeyBundle: ArrayBuffer, username: string): string;
  connectPeer(peerInfo: {peerId: string; address?: string; port?: number; iceBlob?: string}): void;
  send(chatId: string, payload: string | ArrayBuffer): void;
  getHistory(chatId: string, cursor: number, limit: number): HistoryMessage[];
  linkDevice(linkCode: string): void;
  localUsername(): string;
  localIdentityPublicKey(): ArrayBuffer;
  signIdentity(message: ArrayBuffer): ArrayBuffer;
  updateProfile(username: string, password: string): void;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

export default TurboModuleRegistry.getEnforcing<BridgeSpec>('Bridge');
