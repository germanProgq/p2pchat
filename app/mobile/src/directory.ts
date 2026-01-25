// Directory client for global usernames and invites.
export type DirectoryInvite = {
  id: string;
  fromUsername: string;
  toUsername: string;
  status: 'pending' | 'accepted' | 'declined';
  createdAtMs: number;
  updatedAtMs: number;
  fromBundleHex: string;
  fromIce?: string;
  toBundleHex?: string;
  toIce?: string;
};

let directoryUrl = 'http://localhost:8787';

export function setDirectoryUrl(url: string): void {
  directoryUrl = url.endsWith('/') ? url.slice(0, -1) : url;
}

export function getDirectoryUrl(): string {
  return directoryUrl;
}

async function requestJson<T>(path: string, options: RequestInit): Promise<T> {
  const response = await fetch(`${directoryUrl}${path}`, {
    headers: {'Content-Type': 'application/json', ...(options.headers || {})},
    ...options
  });
  const text = await response.text();
  const payload = text ? JSON.parse(text) : null;
  if (!response.ok) {
    const message = payload?.error || payload?.message || response.statusText;
    throw new Error(message);
  }
  return payload as T;
}

export function buildClaimMessage(username: string, nonce: string): string {
  return `p2pchat.username.claim.v1|${username}|${nonce}`;
}

export function buildInviteMessage(params: {
  fromUsername: string;
  toUsername: string;
  fromBundleHex: string;
  fromIce?: string;
  timestampMs: number;
}): string {
  const ice = params.fromIce || '';
  return `p2pchat.invite.v1|${params.fromUsername}|${params.toUsername}|${params.fromBundleHex}|${ice}|${params.timestampMs}`;
}

export function buildInviteAcceptMessage(params: {
  inviteId: string;
  username: string;
  bundleHex: string;
  ice?: string;
  timestampMs: number;
}): string {
  const ice = params.ice || '';
  return `p2pchat.invite.accept.v1|${params.inviteId}|${params.username}|${params.bundleHex}|${ice}|${params.timestampMs}`;
}

export function buildInviteDeclineMessage(params: {
  inviteId: string;
  username: string;
  timestampMs: number;
}): string {
  return `p2pchat.invite.decline.v1|${params.inviteId}|${params.username}|${params.timestampMs}`;
}

export async function requestChallenge(username: string, identityKeyHex: string): Promise<{challengeId: string; nonce: string; expiresAtMs: number}> {
  return requestJson('/v1/challenge', {
    method: 'POST',
    body: JSON.stringify({username, identityKeyHex})
  });
}

export async function claimUsername(params: {
  username: string;
  identityKeyHex: string;
  challengeId: string;
  signatureHex: string;
  bundleHex: string;
  ice?: string;
}): Promise<void> {
  await requestJson('/v1/claim', {
    method: 'POST',
    body: JSON.stringify(params)
  });
}

export async function sendInvite(params: {
  fromUsername: string;
  toUsername: string;
  fromBundleHex: string;
  fromIce?: string;
  signatureHex: string;
  timestampMs: number;
}): Promise<DirectoryInvite> {
  return requestJson('/v1/invites', {
    method: 'POST',
    body: JSON.stringify(params)
  });
}

export async function fetchInvites(username: string, sinceMs?: number): Promise<DirectoryInvite[]> {
  let query = `username=${encodeURIComponent(username)}`;
  if (sinceMs) {
    query += `&since=${encodeURIComponent(String(sinceMs))}`;
  }
  return requestJson(`/v1/invites?${query}`, {method: 'GET'});
}

export async function acceptInvite(params: {
  inviteId: string;
  username: string;
  bundleHex: string;
  ice?: string;
  signatureHex: string;
  timestampMs: number;
}): Promise<DirectoryInvite> {
  return requestJson(`/v1/invites/${params.inviteId}/accept`, {
    method: 'POST',
    body: JSON.stringify(params)
  });
}

export async function declineInvite(params: {
  inviteId: string;
  username: string;
  signatureHex: string;
  timestampMs: number;
}): Promise<DirectoryInvite> {
  return requestJson(`/v1/invites/${params.inviteId}/decline`, {
    method: 'POST',
    body: JSON.stringify(params)
  });
}
