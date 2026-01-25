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

const DEFAULT_DIRECTORY_URLS = [
  (import.meta as any).env?.VITE_P2PCHAT_DIRECTORY_URL,
  (import.meta as any).env?.VITE_P2PCHAT_DIRECTORY_URLS,
  'http://localhost:8787',
  'http://127.0.0.1:8787'
];

function parseUrlList(value: unknown): string[] {
  if (typeof value !== 'string') {
    return [];
  }
  return value
    .split(/[,\s]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function normalizeUrl(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

function uniqueUrls(urls: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const url of urls) {
    const normalized = normalizeUrl(url);
    if (!seen.has(normalized)) {
      seen.add(normalized);
      out.push(normalized);
    }
  }
  return out;
}

function defaultDirectoryUrls(): string[] {
  const expanded: string[] = [];
  for (const value of DEFAULT_DIRECTORY_URLS) {
    expanded.push(...parseUrlList(value));
  }
  return uniqueUrls(expanded);
}

function getStoredDirectoryUrl(): string | null {
  const saved = localStorage.getItem('p2pchat.directory');
  return saved ? normalizeUrl(saved) : null;
}

export function getDirectoryUrl(): string {
  const defaults = defaultDirectoryUrls();
  return getStoredDirectoryUrl() || defaults[0] || 'http://localhost:8787';
}

export function setDirectoryUrl(url: string): void {
  localStorage.setItem('p2pchat.directory', normalizeUrl(url));
}

function getDirectoryCandidates(): string[] {
  const stored = getStoredDirectoryUrl();
  return uniqueUrls([...(stored ? [stored] : []), ...defaultDirectoryUrls()]);
}

async function requestJson<T>(path: string, options: RequestInit): Promise<T> {
  const candidates = getDirectoryCandidates();
  let lastError: Error | null = null;
  for (const base of candidates) {
    try {
      const response = await fetch(`${base}${path}`, {
        headers: {'Content-Type': 'application/json', ...(options.headers || {})},
        ...options,
      });
      const text = await response.text();
      const payload = text ? JSON.parse(text) : null;
      if (!response.ok) {
        const message = payload?.error || payload?.message || response.statusText;
        if (response.status >= 500) {
          lastError = new Error(message);
          continue;
        }
        throw new Error(message);
      }
      if (base !== getStoredDirectoryUrl()) {
        setDirectoryUrl(base);
      }
      return payload as T;
    } catch (err) {
      if (err instanceof TypeError) {
        lastError = err;
        continue;
      }
      throw err;
    }
  }
  throw lastError || new Error('directory unavailable');
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
    body: JSON.stringify({username, identityKeyHex}),
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
    body: JSON.stringify(params),
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
    body: JSON.stringify(params),
  });
}

export async function fetchInvites(username: string, sinceMs?: number): Promise<DirectoryInvite[]> {
  const query = new URLSearchParams({username});
  if (sinceMs) {
    query.set('since', String(sinceMs));
  }
  return requestJson(`/v1/invites?${query.toString()}`, {method: 'GET'});
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
    body: JSON.stringify(params),
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
    body: JSON.stringify(params),
  });
}
