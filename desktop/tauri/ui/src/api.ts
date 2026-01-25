// Desktop UI bridge for Tauri commands. Spec: docs/desktop_app.md.
import {invoke} from '@tauri-apps/api/tauri';
import {listen, UnlistenFn} from '@tauri-apps/api/event';

const tauriAvailable = typeof window !== 'undefined' && typeof (window as any).__TAURI_IPC__ === 'function';
let warnedMissing = false;

function warnMissingTauri() {
  if (warnedMissing) {
    return;
  }
  warnedMissing = true;
  console.warn('Tauri IPC unavailable. Run the UI with cargo tauri dev.');
}

async function invokeSafe<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!tauriAvailable) {
    warnMissingTauri();
    throw new Error('Tauri IPC unavailable. Run the UI with cargo tauri dev.');
  }
  return invoke<T>(cmd, args);
}

async function listenSafe<T>(event: string, handler: (event: {payload: T}) => void): Promise<UnlistenFn> {
  if (!tauriAvailable) {
    warnMissingTauri();
    return async () => {};
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

export async function startCore(config: UiConfig): Promise<void> {
  await invokeSafe('start', {config});
}

export async function stopCore(): Promise<void> {
  await invokeSafe('stop');
}

export async function localBundle(): Promise<string> {
  return invokeSafe('local_bundle');
}

export async function localIce(): Promise<string> {
  return invokeSafe('local_ice');
}

export async function beginLink(): Promise<string> {
  return invokeSafe('begin_link');
}

export async function addContactHex(bundleHex: string, username?: string): Promise<string> {
  return invokeSafe('add_contact_hex', {bundleHex, username});
}

export async function connectPeer(peerId: string, address?: string, port?: number, iceBlob?: string): Promise<void> {
  await invokeSafe('connect_peer', {peerId, address, port, iceBlob});
}

export async function sendText(peerId: string, message: string): Promise<void> {
  await invokeSafe('send_text', {peerId, message});
}

export async function sendBinary(peerId: string, payload: number[]): Promise<void> {
  await invokeSafe('send_binary', {peerId, payload});
}

export async function getHistory(peerId: string, cursor: number, limit: number): Promise<any[]> {
  return invokeSafe('get_history', {peerId, cursor, limit});
}

export async function linkDevice(code: string): Promise<void> {
  await invokeSafe('link_device', {code});
}

export async function localUsername(): Promise<string> {
  return invokeSafe('local_username');
}

export async function identityPublicKeyHex(): Promise<string> {
  return invokeSafe('identity_public_key_hex');
}

export async function signIdentityHex(messageHex: string): Promise<string> {
  return invokeSafe('sign_identity_hex', {messageHex});
}

export async function updateProfile(username?: string, password?: string): Promise<void> {
  await invokeSafe('update_profile', {username, password});
}

export async function onCoreEvent(handler: (event: CoreEvent) => void): Promise<UnlistenFn> {
  return listenSafe<CoreEvent>('core-event', (event) => handler(event.payload));
}
