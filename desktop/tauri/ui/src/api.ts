// Desktop UI bridge for Tauri commands with a browser runtime fallback.
import {invoke} from '@tauri-apps/api/tauri';
import {listen, UnlistenFn} from '@tauri-apps/api/event';
import * as nacl from 'tweetnacl';

const tauriAvailable = typeof window !== 'undefined' && typeof (window as any).__TAURI_IPC__ === 'function';

let warnedMissing = false;

function warnMissingTauri() {
  if (warnedMissing) {
    return;
  }
  warnedMissing = true;
  console.info('Tauri IPC unavailable. Running p2pchat in browser mode.');
}

async function invokeSafe<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!tauriAvailable) {
    warnMissingTauri();
    throw new Error('Tauri IPC unavailable');
  }
  return invoke<T>(cmd, args);
}

async function listenSafe<T>(event: string, handler: (event: {payload: T}) => void): Promise<UnlistenFn> {
  if (!tauriAvailable) {
    warnMissingTauri();
    return () => {};
  }
  return listen<T>(event, handler);
}

export function isTauriAvailable(): boolean {
  return tauriAvailable;
}

export type TransportKind = 'quic' | 'webrtc' | 'loopback';

export type RelayCandidate = {
  type: number;
  address: string;
  port: number;
  priority: number;
};

export type UiConfig = {
  dataDir?: string;
  identityPath?: string;
  storagePath?: string;
  schemaPath?: string;
  username?: string;
  password?: string;
  transportKind?: TransportKind;
  bindAddress?: string;
  bindPort?: number;
  maxDatagramSize?: number;
  maxInFlight?: number;
  maxQueueBytes?: number;
  retryBaseDelayMs?: number;
  retryMaxDelayMs?: number;
  retryMaxAttempts?: number;
  retryJitterRatio?: number;
  stunServers?: string[];
  relayCandidates?: RelayCandidate[];
  oneTimePrekeys?: number;
  signedPrekeyId?: number;
  oneTimeStartId?: number;
  handshakeBaseDelayMs?: number;
  handshakeMaxDelayMs?: number;
  handshakeMaxAttempts?: number;
  tickIntervalMs?: number;
};

export type CoreEvent = {
  event: string;
  payload: any;
};

type BrowserProfile = {
  username: string;
  publicKeyHex: string;
  secretKeyBase64: string;
};

type BrowserContact = {
  peerId: string;
  username?: string;
  bundleHex?: string;
};

type BrowserHistoryMessage = {
  chatId: string;
  msgId: string;
  senderDevice: string;
  peerUsername: string;
  tsMs: number;
  contentType: 'text' | 'binary';
  body: number[];
  delivered: boolean;
  acked: boolean;
  index: number;
};

type BrowserState = {
  contacts: Record<string, BrowserContact>;
  history: Record<string, BrowserHistoryMessage[]>;
};

type BrowserWireMessage = {
  type: 'message';
  toPeerId: string;
  fromPeerId: string;
  fromUsername: string;
  msgId: string;
  body: string;
  tsMs: number;
};

const BROWSER_CHANNEL = 'p2pchat.browser.v1';

function bytesToHex(bytes: Uint8Array): string {
  const out: string[] = [];
  for (const byte of bytes) {
    out.push(byte.toString(16).padStart(2, '0'));
  }
  return out.join('');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^a-fA-F0-9]/g, '');
  const length = clean.length - (clean.length % 2);
  const out = new Uint8Array(length / 2);
  for (let i = 0; i < length; i += 2) {
    out[i / 2] = parseInt(clean.slice(i, i + 2), 16);
  }
  return out;
}

function textToHex(text: string): string {
  return bytesToHex(new TextEncoder().encode(text));
}

function hexToText(hex: string): string {
  return new TextDecoder().decode(hexToBytes(hex));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function randomId(prefix: string): string {
  const bytes = new Uint8Array(12);
  crypto.getRandomValues(bytes);
  return `${prefix}-${bytesToHex(bytes)}`;
}

function parseBundle(bundleHex: string): {peerId: string; username?: string} {
  try {
    const parsed = JSON.parse(hexToText(bundleHex));
    if (typeof parsed.identityKeyHex === 'string') {
      return {
        peerId: parsed.identityKeyHex,
        username: typeof parsed.username === 'string' ? parsed.username : undefined
      };
    }
  } catch {
    // Native bundles are opaque to the browser fallback; derive a stable local id below.
  }
  const fallback = bundleHex.replace(/[^a-fA-F0-9]/g, '').slice(0, 48);
  return {peerId: fallback ? `bundle-${fallback}` : randomId('peer')};
}

function loadJson<T>(key: string, fallback: T): T {
  const raw = localStorage.getItem(key);
  if (!raw) {
    return fallback;
  }
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

class BrowserCore {
  private channel: BroadcastChannel | null = null;
  private handlers = new Set<(event: CoreEvent) => void>();
  private profile: BrowserProfile | null = null;
  private state: BrowserState = {contacts: {}, history: {}};

  start(config: UiConfig): void {
    const username = (config.username || '').trim();
    if (!username) {
      throw new Error('Username required');
    }
    this.profile = this.loadProfile(username);
    this.state = loadJson<BrowserState>(this.stateKey(), {contacts: {}, history: {}});
    this.openChannel();
  }

  stop(): void {
    if (this.channel) {
      this.channel.close();
      this.channel = null;
    }
    this.profile = null;
    this.state = {contacts: {}, history: {}};
  }

  subscribe(handler: (event: CoreEvent) => void): UnlistenFn {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  localBundle(): string {
    const profile = this.requireProfile();
    return textToHex(JSON.stringify({
      version: 1,
      runtime: 'browser',
      username: profile.username,
      identityKeyHex: profile.publicKeyHex,
      createdAtMs: Date.now()
    }));
  }

  localIce(): string {
    const profile = this.requireProfile();
    return JSON.stringify({
      runtime: 'browser',
      channel: BROWSER_CHANNEL,
      username: profile.username,
      peerId: profile.publicKeyHex
    });
  }

  beginLink(): string {
    return randomId('link');
  }

  linkDevice(_code: string): void {
    this.emit('onPeerStatus', {
      peerId: this.localPeerId(),
      peerUsername: this.requireProfile().username,
      status: 'linked'
    });
  }

  addContactHex(bundleHex: string, username?: string): string {
    const parsed = parseBundle(bundleHex);
    const peerId = parsed.peerId;
    this.state.contacts[peerId] = {
      peerId,
      username: username || parsed.username || this.state.contacts[peerId]?.username,
      bundleHex
    };
    this.ensureHistory(peerId);
    this.persistState();
    this.emit('onConnectionChange', {
      peerId,
      peerUsername: this.state.contacts[peerId].username,
      state: 'connected'
    });
    this.emit('onPeerStatus', {
      peerId,
      peerUsername: this.state.contacts[peerId].username,
      status: 'ready'
    });
    return peerId;
  }

  connectPeer(peerId: string, _address?: string, _port?: number, _iceBlob?: string): void {
    this.state.contacts[peerId] = this.state.contacts[peerId] || {peerId};
    this.ensureHistory(peerId);
    this.persistState();
    this.emit('onConnectionChange', {
      peerId,
      peerUsername: this.state.contacts[peerId].username,
      state: 'connected'
    });
    this.emit('onPeerStatus', {
      peerId,
      peerUsername: this.state.contacts[peerId].username,
      status: 'ready'
    });
  }

  sendText(peerId: string, message: string): void {
    const profile = this.requireProfile();
    const msg: BrowserHistoryMessage = {
      chatId: peerId,
      msgId: randomId('msg'),
      senderDevice: profile.publicKeyHex,
      peerUsername: this.state.contacts[peerId]?.username || peerId,
      tsMs: Date.now(),
      contentType: 'text',
      body: Array.from(new TextEncoder().encode(message)),
      delivered: true,
      acked: true,
      index: this.nextIndex(peerId)
    };
    this.appendHistory(peerId, msg);
    this.channel?.postMessage({
      type: 'message',
      toPeerId: peerId,
      fromPeerId: profile.publicKeyHex,
      fromUsername: profile.username,
      msgId: msg.msgId,
      body: message,
      tsMs: msg.tsMs
    } satisfies BrowserWireMessage);
  }

  sendBinary(peerId: string, payload: number[]): void {
    const profile = this.requireProfile();
    const msg: BrowserHistoryMessage = {
      chatId: peerId,
      msgId: randomId('bin'),
      senderDevice: profile.publicKeyHex,
      peerUsername: this.state.contacts[peerId]?.username || peerId,
      tsMs: Date.now(),
      contentType: 'binary',
      body: payload,
      delivered: true,
      acked: true,
      index: this.nextIndex(peerId)
    };
    this.appendHistory(peerId, msg);
  }

  getHistory(peerId: string, _cursor: number, limit: number): BrowserHistoryMessage[] {
    const history = this.state.history[peerId] || [];
    return history.slice(Math.max(0, history.length - limit));
  }

  identityPublicKeyHex(): string {
    return this.requireProfile().publicKeyHex;
  }

  localUsername(): string {
    return this.requireProfile().username;
  }

  signIdentityHex(messageHex: string): string {
    const profile = this.requireProfile();
    const signature = nacl.sign.detached(hexToBytes(messageHex), base64ToBytes(profile.secretKeyBase64));
    return bytesToHex(signature);
  }

  updateProfile(username?: string, _password?: string): void {
    const nextUsername = (username || '').trim();
    if (!nextUsername || nextUsername === this.profile?.username) {
      return;
    }
    this.profile = this.loadProfile(nextUsername);
    this.state = loadJson<BrowserState>(this.stateKey(), {contacts: {}, history: {}});
    this.openChannel();
  }

  private loadProfile(username: string): BrowserProfile {
    const key = `p2pchat.browser.identity.${username}`;
    const stored = loadJson<BrowserProfile | null>(key, null);
    if (stored?.secretKeyBase64 && stored.publicKeyHex) {
      return stored;
    }
    const keyPair = nacl.sign.keyPair();
    const profile: BrowserProfile = {
      username,
      publicKeyHex: bytesToHex(keyPair.publicKey),
      secretKeyBase64: bytesToBase64(keyPair.secretKey)
    };
    localStorage.setItem(key, JSON.stringify(profile));
    return profile;
  }

  private openChannel(): void {
    if (this.channel) {
      this.channel.close();
      this.channel = null;
    }
    if (typeof BroadcastChannel === 'undefined') {
      return;
    }
    this.channel = new BroadcastChannel(BROWSER_CHANNEL);
    this.channel.onmessage = (event) => {
      this.handleWireMessage(event.data as BrowserWireMessage);
    };
  }

  private handleWireMessage(message: BrowserWireMessage): void {
    const profile = this.profile;
    if (!profile || message.type !== 'message' || message.toPeerId !== profile.publicKeyHex) {
      return;
    }
    const peerId = message.fromPeerId;
    this.state.contacts[peerId] = {
      ...(this.state.contacts[peerId] || {peerId}),
      username: message.fromUsername
    };
    const entry: BrowserHistoryMessage = {
      chatId: peerId,
      msgId: message.msgId,
      senderDevice: peerId,
      peerUsername: message.fromUsername,
      tsMs: message.tsMs,
      contentType: 'text',
      body: Array.from(new TextEncoder().encode(message.body)),
      delivered: true,
      acked: true,
      index: this.nextIndex(peerId)
    };
    this.appendHistory(peerId, entry);
    this.emit('onMessage', entry);
    this.emit('onConnectionChange', {
      peerId,
      peerUsername: message.fromUsername,
      state: 'connected'
    });
    this.emit('onPeerStatus', {
      peerId,
      peerUsername: message.fromUsername,
      status: 'ready'
    });
  }

  private emit(event: string, payload: any): void {
    for (const handler of this.handlers) {
      handler({event, payload});
    }
  }

  private localPeerId(): string {
    return this.requireProfile().publicKeyHex;
  }

  private requireProfile(): BrowserProfile {
    if (!this.profile) {
      throw new Error('core not started');
    }
    return this.profile;
  }

  private stateKey(): string {
    return `p2pchat.browser.state.${this.requireProfile().username}`;
  }

  private ensureHistory(peerId: string): BrowserHistoryMessage[] {
    if (!this.state.history[peerId]) {
      this.state.history[peerId] = [];
    }
    return this.state.history[peerId];
  }

  private nextIndex(peerId: string): number {
    return this.ensureHistory(peerId).length + 1;
  }

  private appendHistory(peerId: string, msg: BrowserHistoryMessage): void {
    const history = this.ensureHistory(peerId);
    if (!history.some((entry) => entry.msgId === msg.msgId)) {
      history.push(msg);
      this.persistState();
    }
  }

  private persistState(): void {
    if (!this.profile) {
      return;
    }
    localStorage.setItem(this.stateKey(), JSON.stringify(this.state));
  }
}

const browserCore = new BrowserCore();

export async function startCore(config: UiConfig): Promise<void> {
  if (!tauriAvailable) {
    warnMissingTauri();
    browserCore.start(config);
    return;
  }
  await invokeSafe('start', {config});
}

export async function stopCore(): Promise<void> {
  if (!tauriAvailable) {
    browserCore.stop();
    return;
  }
  await invokeSafe('stop');
}

export async function localBundle(): Promise<string> {
  if (!tauriAvailable) {
    return browserCore.localBundle();
  }
  return invokeSafe('local_bundle');
}

export async function localIce(): Promise<string> {
  if (!tauriAvailable) {
    return browserCore.localIce();
  }
  return invokeSafe('local_ice');
}

export async function beginLink(): Promise<string> {
  if (!tauriAvailable) {
    return browserCore.beginLink();
  }
  return invokeSafe('begin_link');
}

export async function addContactHex(bundleHex: string, username?: string): Promise<string> {
  if (!tauriAvailable) {
    return browserCore.addContactHex(bundleHex, username);
  }
  return invokeSafe('add_contact_hex', {bundleHex, username});
}

export async function connectPeer(peerId: string, address?: string, port?: number, iceBlob?: string): Promise<void> {
  if (!tauriAvailable) {
    browserCore.connectPeer(peerId, address, port, iceBlob);
    return;
  }
  await invokeSafe('connect_peer', {peerId, address, port, iceBlob});
}

export async function sendText(peerId: string, message: string): Promise<void> {
  if (!tauriAvailable) {
    browserCore.sendText(peerId, message);
    return;
  }
  await invokeSafe('send_text', {peerId, message});
}

export async function sendBinary(peerId: string, payload: number[]): Promise<void> {
  if (!tauriAvailable) {
    browserCore.sendBinary(peerId, payload);
    return;
  }
  await invokeSafe('send_binary', {peerId, payload});
}

export async function getHistory(peerId: string, cursor: number, limit: number): Promise<any[]> {
  if (!tauriAvailable) {
    return browserCore.getHistory(peerId, cursor, limit);
  }
  return invokeSafe('get_history', {peerId, cursor, limit});
}

export async function linkDevice(code: string): Promise<void> {
  if (!tauriAvailable) {
    browserCore.linkDevice(code);
    return;
  }
  await invokeSafe('link_device', {code});
}

export async function localUsername(): Promise<string> {
  if (!tauriAvailable) {
    return browserCore.localUsername();
  }
  return invokeSafe('local_username');
}

export async function identityPublicKeyHex(): Promise<string> {
  if (!tauriAvailable) {
    return browserCore.identityPublicKeyHex();
  }
  return invokeSafe('identity_public_key_hex');
}

export async function signIdentityHex(messageHex: string): Promise<string> {
  if (!tauriAvailable) {
    return browserCore.signIdentityHex(messageHex);
  }
  return invokeSafe('sign_identity_hex', {messageHex});
}

export async function updateProfile(username?: string, password?: string): Promise<void> {
  if (!tauriAvailable) {
    browserCore.updateProfile(username, password);
    return;
  }
  await invokeSafe('update_profile', {username, password});
}

export async function onCoreEvent(handler: (event: CoreEvent) => void): Promise<UnlistenFn> {
  if (!tauriAvailable) {
    return browserCore.subscribe(handler);
  }
  return listenSafe<CoreEvent>('core-event', (event) => handler(event.payload));
}
