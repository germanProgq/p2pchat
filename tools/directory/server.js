// Directory service for global usernames and invite routing.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const cors = require('cors');
const express = require('express');
const nacl = require('tweetnacl');

const PORT = Number(process.env.PORT || 8787);
const DATA_PATH = process.env.P2PCHAT_DIRECTORY_DATA || path.join(__dirname, 'data.json');
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

const USERNAME_RE = /^[A-Za-z0-9._-]{3,32}$/;

function nowMs() {
  return Date.now();
}

function loadStore(filePath) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      users: parsed.users || {},
      invites: parsed.invites || {},
      challenges: parsed.challenges || {}
    };
  } catch (err) {
    return {users: {}, invites: {}, challenges: {}};
  }
}

const store = loadStore(DATA_PATH);

function saveStore() {
  const tmpPath = `${DATA_PATH}.tmp`;
  const payload = JSON.stringify(store, null, 2);
  fs.writeFileSync(tmpPath, payload, 'utf8');
  fs.renameSync(tmpPath, DATA_PATH);
}

function requireString(value, name) {
  if (typeof value !== 'string' || value.trim().length === 0) {
    throw new Error(`${name} required`);
  }
  return value.trim();
}

function validateUsername(username) {
  if (!USERNAME_RE.test(username)) {
    throw new Error('username must be 3-32 chars of letters, numbers, ., -, _');
  }
  return username;
}

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0) {
    return null;
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    const byte = parseInt(hex.slice(i, i + 2), 16);
    if (Number.isNaN(byte)) {
      return null;
    }
    out[i / 2] = byte;
  }
  return out;
}

function ensureHexBytes(hex, length, name) {
  const bytes = hexToBytes(hex);
  if (!bytes || (length && bytes.length !== length)) {
    throw new Error(`${name} must be ${length} bytes`);
  }
  return bytes;
}

function ensureHexBytesAtLeast(hex, minLength, name) {
  const bytes = hexToBytes(hex);
  if (!bytes || bytes.length < minLength) {
    throw new Error(`${name} must be at least ${minLength} bytes`);
  }
  return bytes;
}

function verifySignature(message, signatureHex, publicKeyHex) {
  const sig = ensureHexBytes(signatureHex, 64, 'signature');
  const pub = ensureHexBytes(publicKeyHex, 32, 'identityKey');
  const msgBytes = new TextEncoder().encode(message);
  return nacl.sign.detached.verify(msgBytes, sig, pub);
}

function errorResponse(res, status, message) {
  return res.status(status).json({error: message});
}

function pruneChallenges() {
  const now = nowMs();
  for (const [id, challenge] of Object.entries(store.challenges)) {
    if (challenge.expiresAtMs <= now) {
      delete store.challenges[id];
    }
  }
}

const app = express();
app.use(cors());
app.use(express.json({limit: '2mb'}));

app.get('/health', (_req, res) => {
  res.json({ok: true, nowMs: nowMs()});
});

app.post('/v1/challenge', (req, res) => {
  try {
    pruneChallenges();
    const username = validateUsername(requireString(req.body.username, 'username'));
    const identityKeyHex = requireString(req.body.identityKeyHex, 'identityKeyHex');
    ensureHexBytes(identityKeyHex, 32, 'identityKey');

    const challengeId = crypto.randomUUID();
    const nonce = crypto.randomBytes(16).toString('hex');
    const expiresAtMs = nowMs() + CHALLENGE_TTL_MS;
    store.challenges[challengeId] = {username, identityKeyHex, nonce, expiresAtMs};
    saveStore();

    res.json({challengeId, nonce, expiresAtMs});
  } catch (err) {
    errorResponse(res, 400, err.message || 'invalid request');
  }
});

app.post('/v1/claim', (req, res) => {
  try {
    pruneChallenges();
    const username = validateUsername(requireString(req.body.username, 'username'));
    const identityKeyHex = requireString(req.body.identityKeyHex, 'identityKeyHex');
    const challengeId = requireString(req.body.challengeId, 'challengeId');
    const signatureHex = requireString(req.body.signatureHex, 'signatureHex');
    const bundleHex = requireString(req.body.bundleHex, 'bundleHex');
    const ice = typeof req.body.ice === 'string' && req.body.ice.trim().length > 0 ? req.body.ice.trim() : undefined;

    ensureHexBytes(identityKeyHex, 32, 'identityKey');
    ensureHexBytesAtLeast(bundleHex, 1, 'bundle');

    const challenge = store.challenges[challengeId];
    if (!challenge) {
      return errorResponse(res, 404, 'challenge not found');
    }
    if (challenge.username !== username || challenge.identityKeyHex !== identityKeyHex) {
      return errorResponse(res, 400, 'challenge mismatch');
    }
    if (challenge.expiresAtMs <= nowMs()) {
      delete store.challenges[challengeId];
      saveStore();
      return errorResponse(res, 400, 'challenge expired');
    }

    const message = `p2pchat.username.claim.v1|${username}|${challenge.nonce}`;
    if (!verifySignature(message, signatureHex, identityKeyHex)) {
      return errorResponse(res, 401, 'signature invalid');
    }

    const existing = store.users[username];
    if (existing && existing.identityKeyHex !== identityKeyHex) {
      return errorResponse(res, 409, 'username already claimed');
    }

    store.users[username] = {
      username,
      identityKeyHex,
      bundleHex,
      ice,
      updatedAtMs: nowMs()
    };
    delete store.challenges[challengeId];
    saveStore();

    res.json({ok: true});
  } catch (err) {
    errorResponse(res, 400, err.message || 'invalid request');
  }
});

app.post('/v1/invites', (req, res) => {
  try {
    const fromUsername = validateUsername(requireString(req.body.fromUsername, 'fromUsername'));
    const toUsername = validateUsername(requireString(req.body.toUsername, 'toUsername'));
    const fromBundleHex = requireString(req.body.fromBundleHex, 'fromBundleHex');
    const fromIce = typeof req.body.fromIce === 'string' ? req.body.fromIce.trim() : '';
    const signatureHex = requireString(req.body.signatureHex, 'signatureHex');
    const timestampMs = Number(req.body.timestampMs);

    ensureHexBytesAtLeast(fromBundleHex, 1, 'fromBundle');
    if (!Number.isFinite(timestampMs)) {
      throw new Error('timestampMs required');
    }

    const fromUser = store.users[fromUsername];
    const toUser = store.users[toUsername];
    if (!fromUser) {
      return errorResponse(res, 404, 'from username not claimed');
    }
    if (!toUser) {
      return errorResponse(res, 404, 'to username not claimed');
    }

    const message = `p2pchat.invite.v1|${fromUsername}|${toUsername}|${fromBundleHex}|${fromIce}|${timestampMs}`;
    if (!verifySignature(message, signatureHex, fromUser.identityKeyHex)) {
      return errorResponse(res, 401, 'signature invalid');
    }

    const id = crypto.randomUUID();
    const now = nowMs();
    const invite = {
      id,
      fromUsername,
      toUsername,
      status: 'pending',
      createdAtMs: now,
      updatedAtMs: now,
      fromBundleHex,
      fromIce: fromIce || undefined
    };
    store.invites[id] = invite;
    saveStore();

    res.json(invite);
  } catch (err) {
    errorResponse(res, 400, err.message || 'invalid request');
  }
});

app.get('/v1/invites', (req, res) => {
  try {
    const username = validateUsername(requireString(req.query.username, 'username'));
    const sinceParam = typeof req.query.since === 'string' ? Number(req.query.since) : undefined;
    const sinceMs = Number.isFinite(sinceParam) ? sinceParam : undefined;
    const results = Object.values(store.invites).filter((invite) => {
      const match = invite.fromUsername === username || invite.toUsername === username;
      if (!match) {
        return false;
      }
      if (sinceMs && invite.updatedAtMs <= sinceMs) {
        return false;
      }
      return true;
    });
    results.sort((a, b) => b.updatedAtMs - a.updatedAtMs);
    res.json(results);
  } catch (err) {
    errorResponse(res, 400, err.message || 'invalid request');
  }
});

app.post('/v1/invites/:id/accept', (req, res) => {
  try {
    const inviteId = requireString(req.params.id, 'inviteId');
    const username = validateUsername(requireString(req.body.username, 'username'));
    const bundleHex = requireString(req.body.bundleHex, 'bundleHex');
    const ice = typeof req.body.ice === 'string' ? req.body.ice.trim() : '';
    const signatureHex = requireString(req.body.signatureHex, 'signatureHex');
    const timestampMs = Number(req.body.timestampMs);

    ensureHexBytesAtLeast(bundleHex, 1, 'bundle');
    if (!Number.isFinite(timestampMs)) {
      throw new Error('timestampMs required');
    }

    const invite = store.invites[inviteId];
    if (!invite) {
      return errorResponse(res, 404, 'invite not found');
    }
    if (invite.status !== 'pending') {
      return errorResponse(res, 409, `invite already ${invite.status}`);
    }
    if (invite.toUsername !== username) {
      return errorResponse(res, 403, 'invite not addressed to user');
    }

    const user = store.users[username];
    if (!user) {
      return errorResponse(res, 404, 'username not claimed');
    }

    const message = `p2pchat.invite.accept.v1|${inviteId}|${username}|${bundleHex}|${ice}|${timestampMs}`;
    if (!verifySignature(message, signatureHex, user.identityKeyHex)) {
      return errorResponse(res, 401, 'signature invalid');
    }

    invite.status = 'accepted';
    invite.toBundleHex = bundleHex;
    invite.toIce = ice || undefined;
    invite.updatedAtMs = nowMs();
    saveStore();

    res.json(invite);
  } catch (err) {
    errorResponse(res, 400, err.message || 'invalid request');
  }
});

app.post('/v1/invites/:id/decline', (req, res) => {
  try {
    const inviteId = requireString(req.params.id, 'inviteId');
    const username = validateUsername(requireString(req.body.username, 'username'));
    const signatureHex = requireString(req.body.signatureHex, 'signatureHex');
    const timestampMs = Number(req.body.timestampMs);

    if (!Number.isFinite(timestampMs)) {
      throw new Error('timestampMs required');
    }

    const invite = store.invites[inviteId];
    if (!invite) {
      return errorResponse(res, 404, 'invite not found');
    }
    if (invite.status !== 'pending') {
      return errorResponse(res, 409, `invite already ${invite.status}`);
    }
    if (invite.toUsername !== username) {
      return errorResponse(res, 403, 'invite not addressed to user');
    }

    const user = store.users[username];
    if (!user) {
      return errorResponse(res, 404, 'username not claimed');
    }

    const message = `p2pchat.invite.decline.v1|${inviteId}|${username}|${timestampMs}`;
    if (!verifySignature(message, signatureHex, user.identityKeyHex)) {
      return errorResponse(res, 401, 'signature invalid');
    }

    invite.status = 'declined';
    invite.updatedAtMs = nowMs();
    saveStore();

    res.json(invite);
  } catch (err) {
    errorResponse(res, 400, err.message || 'invalid request');
  }
});

app.listen(PORT, () => {
  console.log(`p2pchat directory listening on :${PORT}`);
});
