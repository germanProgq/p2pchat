// Desktop UI layout and interactions. Spec: docs/desktop_app.md.
import React, {useCallback, useEffect, useMemo, useState} from 'react';
import {
  addContactHex,
  beginLink,
  connectPeer,
  getHistory,
  identityPublicKeyHex,
  linkDevice,
  localBundle,
  localIce,
  onCoreEvent,
  sendText,
  signIdentityHex,
  startCore,
  updateProfile,
  UiConfig
} from './api';
import {
  acceptInvite,
  buildClaimMessage,
  buildInviteAcceptMessage,
  buildInviteDeclineMessage,
  buildInviteMessage,
  claimUsername,
  declineInvite,
  DirectoryInvite,
  fetchInvites,
  requestChallenge,
  sendInvite
} from './directory';

type ContentType = 'text' | 'binary';

type Message = {
  id: string;
  chatId: string;
  tsMs: number;
  contentType: ContentType;
  body: string;
  outgoing: boolean;
  pending?: boolean;
};

type ChatMeta = {
  id: string;
  username?: string;
  lastMessage?: string;
  lastTs?: number;
  connection?: string;
  status?: string;
};

type Toast = {
  id: string;
  message: string;
};

const DEFAULT_CONFIG: UiConfig = {
  transportKind: 'quic',
  bindAddress: '0.0.0.0',
  bindPort: 0,
  tickIntervalMs: 50
};

const AUTO_STUN_SERVERS = [
  'stun:stun.l.google.com:19302',
  'stun:stun1.l.google.com:19302',
  'stun:stun2.l.google.com:19302'
];

const AUTO_TRANSPORT_PRESETS: Array<Partial<UiConfig>> = [
  {transportKind: 'quic', bindAddress: '0.0.0.0', bindPort: 0, tickIntervalMs: DEFAULT_CONFIG.tickIntervalMs},
  {transportKind: 'webrtc', bindAddress: '0.0.0.0', bindPort: 0, tickIntervalMs: DEFAULT_CONFIG.tickIntervalMs},
  {transportKind: 'loopback', bindAddress: '127.0.0.1', bindPort: 0, tickIntervalMs: DEFAULT_CONFIG.tickIntervalMs}
];

const USERNAME_RE = /^[A-Za-z0-9._-]{3,32}$/;

const formatTime = (ts: number) => {
  const date = new Date(ts);
  return date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
};

const decodeBody = (contentType: ContentType, body: number[] | string) => {
  if (contentType !== 'text') {
    if (typeof body === 'string') {
      return body;
    }
    return `Binary (${body.length} bytes)`;
  }
  if (typeof body === 'string') {
    return body;
  }
  const decoder = new TextDecoder();
  return decoder.decode(Uint8Array.from(body));
};

const bytesToHex = (bytes: Uint8Array) => {
  const hex: string[] = [];
  for (const byte of bytes) {
    hex.push(byte.toString(16).padStart(2, '0'));
  }
  return hex.join('');
};

const messageToHex = (message: string) => {
  return bytesToHex(new TextEncoder().encode(message));
};

const mergeInvites = (prev: DirectoryInvite[], incoming: DirectoryInvite[]) => {
  const map = new Map(prev.map((invite) => [invite.id, invite]));
  for (const invite of incoming) {
    const existing = map.get(invite.id);
    map.set(invite.id, existing ? {...existing, ...invite} : invite);
  }
  return Array.from(map.values()).sort((a, b) => b.updatedAtMs - a.updatedAtMs);
};

const isValidUsername = (username: string) => USERNAME_RE.test(username);

const isValidPassword = (password: string) => password.length >= 8 && password.length <= 128;

const withAutoDefaults = (config: UiConfig): UiConfig => {
  const next: UiConfig = {...DEFAULT_CONFIG, ...config};
  if (next.transportKind === 'webrtc' && (!next.stunServers || next.stunServers.length === 0)) {
    next.stunServers = AUTO_STUN_SERVERS;
  }
  return next;
};

const buildConfigCandidates = (base: UiConfig): UiConfig[] => {
  const candidates: UiConfig[] = [];
  const seen = new Set<string>();
  const push = (config: UiConfig) => {
    const normalized = withAutoDefaults(config);
    const {password: _ignored, ...safeKey} = normalized;
    const key = JSON.stringify(safeKey);
    if (!seen.has(key)) {
      seen.add(key);
      candidates.push(normalized);
    }
  };
  push(base);
  for (const preset of AUTO_TRANSPORT_PRESETS) {
    push({...base, ...preset});
  }
  return candidates;
};

export default function App() {
  const [config, setConfig] = useState<UiConfig>(() => {
    const saved = localStorage.getItem('p2pchat.config');
    if (!saved) {
      return DEFAULT_CONFIG;
    }
    try {
      return {...DEFAULT_CONFIG, ...JSON.parse(saved)};
    } catch {
      return DEFAULT_CONFIG;
    }
  });
  const [authUsername, setAuthUsername] = useState(() => localStorage.getItem('p2pchat.username') || '');
  const [authPassword, setAuthPassword] = useState('');
  const [sessionPassword, setSessionPassword] = useState('');
  const [authError, setAuthError] = useState('');
  const [ready, setReady] = useState(false);
  const [starting, setStarting] = useState(false);
  const [localUsername, setLocalUsername] = useState('');
  const [chats, setChats] = useState<Record<string, ChatMeta>>({});
  const [messages, setMessages] = useState<Record<string, Message[]>>({});
  const [selectedChat, setSelectedChat] = useState<string | null>(null);
  const [composer, setComposer] = useState('');
  const [bundleHex, setBundleHex] = useState('');
  const [contactUsername, setContactUsername] = useState('');
  const [linkCode, setLinkCode] = useState('');
  const [connectPeerId, setConnectPeerId] = useState('');
  const [connectAddress, setConnectAddress] = useState('');
  const [connectPort, setConnectPort] = useState('');
  const [connectIce, setConnectIce] = useState('');
  const [linkInput, setLinkInput] = useState('');
  const [inviteUsername, setInviteUsername] = useState('');
  const [invites, setInvites] = useState<DirectoryInvite[]>([]);
  const [lastInviteSync, setLastInviteSync] = useState<number>(0);
  const [profileUsername, setProfileUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [menuOpen, setMenuOpen] = useState(false);
  const processedInvites = React.useRef<Set<string>>(new Set());

  const effectiveUsername = localUsername || authUsername.trim();

  const chatList = useMemo(() => {
    return Object.values(chats)
      .sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
  }, [chats]);

  const activeMessages = selectedChat ? messages[selectedChat] || [] : [];
  const selectedMeta = selectedChat ? chats[selectedChat] : undefined;

  const incomingInvites = useMemo(() => {
    return invites.filter((invite) => invite.toUsername === effectiveUsername && invite.status === 'pending');
  }, [effectiveUsername, invites]);

  const outgoingInvites = useMemo(() => {
    return invites.filter((invite) => invite.fromUsername === effectiveUsername);
  }, [effectiveUsername, invites]);

  const pushToast = useCallback((message: string) => {
    const id = `${Date.now()}-${Math.random()}`;
    setToasts((prev) => [...prev, {id, message}]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((toast) => toast.id !== id));
    }, 4500);
  }, []);

  const claimDirectoryUsername = useCallback(async (username: string) => {
    const identityKey = await identityPublicKeyHex();
    const challenge = await requestChallenge(username, identityKey);
    const message = buildClaimMessage(username, challenge.nonce);
    const signature = await signIdentityHex(messageToHex(message));
    const bundle = await localBundle();
    const ice = await localIce();
    await claimUsername({
      username,
      identityKeyHex: identityKey,
      challengeId: challenge.challengeId,
      signatureHex: signature,
      bundleHex: bundle,
      ice
    });
  }, []);

  const handleStart = useCallback(async () => {
    if (starting) {
      return;
    }
    setStarting(true);
    setAuthError('');
    const username = authUsername.trim();
    const password = authPassword || sessionPassword;
    const nextConfig: UiConfig = {
      ...config,
      username,
      password
    };
    if (!username) {
      setAuthError('Username required');
      setStarting(false);
      return;
    }
    if (!isValidUsername(username)) {
      setAuthError('Username must be 3-32 chars of letters, numbers, ., -, _');
      setStarting(false);
      return;
    }
    if (!password) {
      setAuthError('Password required');
      setStarting(false);
      return;
    }
    if (!isValidPassword(password)) {
      setAuthError('Password must be 8-128 characters');
      setStarting(false);
      return;
    }

    localStorage.setItem('p2pchat.username', username);

    try {
      const candidates = buildConfigCandidates(nextConfig);
      let lastError: unknown = null;
      let activeConfig: UiConfig | null = null;
      for (const candidate of candidates) {
        try {
          await startCore(candidate);
          activeConfig = candidate;
          break;
        } catch (err) {
          lastError = err;
        }
      }
      if (!activeConfig) {
        throw lastError || new Error('Failed to start core');
      }
      const {password: _ignored, ...safeConfig} = activeConfig;
      localStorage.setItem('p2pchat.config', JSON.stringify(safeConfig));
      setConfig(safeConfig);
      setReady(true);
      setLocalUsername(username);
      setProfileUsername(username);
      setSessionPassword(password);
      setAuthPassword('');
      try {
        await claimDirectoryUsername(username);
      } catch (err) {
        pushToast(`Directory claim failed: ${String(err)}`);
      }
    } catch (err) {
      const message = String(err);
      setAuthError(message);
      pushToast(message);
      setReady(false);
    } finally {
      setStarting(false);
    }
  }, [authPassword, authUsername, claimDirectoryUsername, config, pushToast, sessionPassword, starting]);

  const handleUpdateProfile = useCallback(async () => {
    if (!ready) {
      return;
    }
    const nextUsername = profileUsername.trim();
    const passwordUpdate = newPassword.trim();
    if (nextUsername && !isValidUsername(nextUsername)) {
      pushToast('Username must be 3-32 chars of letters, numbers, ., -, _');
      return;
    }
    if (passwordUpdate && !isValidPassword(passwordUpdate)) {
      pushToast('Password must be 8-128 characters');
      return;
    }
    try {
      if (nextUsername && nextUsername !== localUsername) {
        await claimDirectoryUsername(nextUsername);
      }
      await updateProfile(nextUsername === localUsername ? '' : nextUsername, passwordUpdate);
      if (nextUsername && nextUsername !== localUsername) {
        setLocalUsername(nextUsername);
        setAuthUsername(nextUsername);
        setProfileUsername(nextUsername);
        localStorage.setItem('p2pchat.username', nextUsername);
      }
      if (passwordUpdate) {
        setSessionPassword(passwordUpdate);
        setNewPassword('');
      }
      pushToast('Profile updated');
    } catch (err) {
      pushToast(String(err));
    }
  }, [claimDirectoryUsername, localUsername, newPassword, profileUsername, pushToast, ready]);

  const refreshInvites = useCallback(async () => {
    if (!effectiveUsername) {
      return;
    }
    try {
      const fetched = await fetchInvites(effectiveUsername, lastInviteSync || undefined);
      if (fetched.length === 0) {
        return;
      }
      setInvites((prev) => mergeInvites(prev, fetched));
      const maxUpdated = fetched.reduce((acc, invite) => Math.max(acc, invite.updatedAtMs), lastInviteSync);
      setLastInviteSync(maxUpdated);
      for (const invite of fetched) {
        if (invite.status === 'accepted' && invite.fromUsername === effectiveUsername && invite.toBundleHex) {
          if (processedInvites.current.has(invite.id)) {
            continue;
          }
          processedInvites.current.add(invite.id);
          try {
            const peerId = await addContactHex(invite.toBundleHex, invite.toUsername);
            setChats((prev) => ({
              ...prev,
              [peerId]: {id: peerId, username: invite.toUsername, lastMessage: 'Invite accepted'}
            }));
            if (invite.toIce) {
              await connectPeer(peerId, undefined, undefined, invite.toIce);
            }
          } catch (err) {
            processedInvites.current.delete(invite.id);
            pushToast(String(err));
          }
        }
      }
    } catch (err) {
      pushToast(String(err));
    }
  }, [effectiveUsername, lastInviteSync, pushToast]);

  const handleSendInvite = useCallback(async () => {
    const toUsername = inviteUsername.trim();
    if (!effectiveUsername) {
      pushToast('Unlock the app first');
      return;
    }
    if (!toUsername) {
      pushToast('Username required');
      return;
    }
    if (toUsername === effectiveUsername) {
      pushToast('Cannot invite yourself');
      return;
    }
    try {
      const bundleHex = await localBundle();
      const ice = await localIce();
      const timestampMs = Date.now();
      const message = buildInviteMessage({
        fromUsername: effectiveUsername,
        toUsername,
        fromBundleHex: bundleHex,
        fromIce: ice,
        timestampMs
      });
      const signatureHex = await signIdentityHex(messageToHex(message));
      const invite = await sendInvite({
        fromUsername: effectiveUsername,
        toUsername,
        fromBundleHex: bundleHex,
        fromIce: ice,
        signatureHex,
        timestampMs
      });
      setInvites((prev) => mergeInvites(prev, [invite]));
      setInviteUsername('');
    } catch (err) {
      pushToast(String(err));
    }
  }, [effectiveUsername, inviteUsername, pushToast]);

  const handleAcceptInvite = useCallback(async (invite: DirectoryInvite) => {
    if (!effectiveUsername) {
      return;
    }
    try {
      const bundleHex = await localBundle();
      const ice = await localIce();
      const timestampMs = Date.now();
      const message = buildInviteAcceptMessage({
        inviteId: invite.id,
        username: effectiveUsername,
        bundleHex,
        ice,
        timestampMs
      });
      const signatureHex = await signIdentityHex(messageToHex(message));
      const updated = await acceptInvite({
        inviteId: invite.id,
        username: effectiveUsername,
        bundleHex,
        ice,
        signatureHex,
        timestampMs
      });
      setInvites((prev) => mergeInvites(prev, [updated]));
      const peerId = await addContactHex(invite.fromBundleHex, invite.fromUsername);
      setChats((prev) => ({
        ...prev,
        [peerId]: {id: peerId, username: invite.fromUsername, lastMessage: 'Invite accepted'}
      }));
      setSelectedChat(peerId);
      if (invite.fromIce) {
        await connectPeer(peerId, undefined, undefined, invite.fromIce);
      }
      processedInvites.current.add(invite.id);
    } catch (err) {
      pushToast(String(err));
    }
  }, [effectiveUsername, pushToast]);

  const handleDeclineInvite = useCallback(async (invite: DirectoryInvite) => {
    if (!effectiveUsername) {
      return;
    }
    try {
      const timestampMs = Date.now();
      const message = buildInviteDeclineMessage({
        inviteId: invite.id,
        username: effectiveUsername,
        timestampMs
      });
      const signatureHex = await signIdentityHex(messageToHex(message));
      const updated = await declineInvite({
        inviteId: invite.id,
        username: effectiveUsername,
        signatureHex,
        timestampMs
      });
      setInvites((prev) => mergeInvites(prev, [updated]));
    } catch (err) {
      pushToast(String(err));
    }
  }, [effectiveUsername, pushToast]);

  useEffect(() => {
    let unlisten: (() => void) | null = null;
    onCoreEvent((event) => {
      if (event.event === 'onMessage') {
        const payload = event.payload;
        const chatId = payload.chatId as string;
        const peerUsername = payload.peerUsername as string | undefined;
        const msg: Message = {
          id: payload.msgId,
          chatId,
          tsMs: payload.tsMs,
          contentType: payload.contentType,
          body: decodeBody(payload.contentType, payload.body),
          outgoing: false
        };
        setMessages((prev) => ({
          ...prev,
          [chatId]: [...(prev[chatId] || []), msg]
        }));
        setChats((prev) => ({
          ...prev,
          [chatId]: {
            ...(prev[chatId] || {id: chatId}),
            id: chatId,
            username: peerUsername || prev[chatId]?.username,
            lastMessage: msg.body,
            lastTs: msg.tsMs
          }
        }));
      }
      if (event.event === 'onConnectionChange') {
        const payload = event.payload;
        const chatId = payload.peerId as string;
        setChats((prev) => ({
          ...prev,
          [chatId]: {
            ...(prev[chatId] || {id: chatId}),
            id: chatId,
            username: payload.peerUsername || prev[chatId]?.username,
            connection: payload.state
          }
        }));
      }
      if (event.event === 'onPeerStatus') {
        const payload = event.payload;
        const chatId = payload.peerId as string;
        setChats((prev) => ({
          ...prev,
          [chatId]: {
            ...(prev[chatId] || {id: chatId}),
            id: chatId,
            username: payload.peerUsername || prev[chatId]?.username,
            status: payload.status
          }
        }));
      }
      if (event.event === 'onError') {
        const payload = event.payload;
        pushToast(payload.message || 'Core error');
      }
    }).then((listener) => {
      unlisten = listener;
    });

    return () => {
      if (unlisten) {
        unlisten();
      }
    };
  }, [pushToast]);

  useEffect(() => {
    if (!ready) {
      return;
    }
    const interval = window.setInterval(() => {
      refreshInvites();
    }, 5000);
    refreshInvites();
    return () => window.clearInterval(interval);
  }, [ready, refreshInvites]);

  useEffect(() => {
    if (!selectedChat) {
      return;
    }
    getHistory(selectedChat, 1, 200)
      .then((history) => {
        const mapped: Message[] = history.map((entry: any) => ({
          id: entry.msgId,
          chatId: entry.chatId,
          tsMs: entry.tsMs,
          contentType: entry.contentType,
          body: decodeBody(entry.contentType, entry.body),
          outgoing: entry.senderDevice !== selectedChat
        }));
        setMessages((prev) => ({
          ...prev,
          [selectedChat]: mapped
        }));
        const peerUsername = history.find((entry: any) => entry.peerUsername)?.peerUsername;
        if (peerUsername) {
          setChats((prev) => ({
            ...prev,
            [selectedChat]: {
              ...(prev[selectedChat] || {id: selectedChat}),
              username: peerUsername
            }
          }));
        }
      })
      .catch((err) => pushToast(String(err)));
  }, [selectedChat, pushToast]);

  const handleSend = async () => {
    if (!selectedChat || !composer.trim()) {
      return;
    }
    const text = composer.trim();
    setComposer('');
    const msg: Message = {
      id: `local-${Date.now()}`,
      chatId: selectedChat,
      tsMs: Date.now(),
      contentType: 'text',
      body: text,
      outgoing: true,
      pending: true
    };
    setMessages((prev) => ({
      ...prev,
      [selectedChat]: [...(prev[selectedChat] || []), msg]
    }));
    setChats((prev) => ({
      ...prev,
      [selectedChat]: {
        ...(prev[selectedChat] || {id: selectedChat}),
        id: selectedChat,
        lastMessage: text,
        lastTs: msg.tsMs
      }
    }));
    try {
      await sendText(selectedChat, text);
    } catch (err) {
      pushToast(String(err));
    }
  };

  const handleAddContact = async () => {
    if (!bundleHex.trim()) {
      pushToast('Paste a bundle hex string');
      return;
    }
    try {
      const username = contactUsername.trim();
      const peerId = await addContactHex(bundleHex.trim(), username || undefined);
      setChats((prev) => ({
        ...prev,
        [peerId]: {id: peerId, username: username || prev[peerId]?.username, lastMessage: 'Contact added'}
      }));
      setBundleHex('');
      setContactUsername('');
      setSelectedChat(peerId);
    } catch (err) {
      pushToast(String(err));
    }
  };

  const handleConnect = async () => {
    if (!connectPeerId.trim()) {
      pushToast('Peer id required');
      return;
    }
    try {
      const port = connectPort ? Number(connectPort) : undefined;
      await connectPeer(connectPeerId.trim(), connectAddress || undefined, port, connectIce || undefined);
      setConnectAddress('');
      setConnectPort('');
      setConnectIce('');
    } catch (err) {
      pushToast(String(err));
    }
  };

  const handleBeginLink = async () => {
    try {
      const code = await beginLink();
      setLinkCode(code);
    } catch (err) {
      pushToast(String(err));
    }
  };

  const handleLinkDevice = async () => {
    if (!linkInput.trim()) {
      pushToast('Link code required');
      return;
    }
    try {
      await linkDevice(linkInput.trim());
      setLinkInput('');
    } catch (err) {
      pushToast(String(err));
    }
  };

  if (!ready) {
    return (
      <div className="auth-screen">
        <div className="auth-card">
          <div className="auth-header">
            <h1>p2pchat</h1>
            <p>Unlock your identity</p>
          </div>
          <label>
            Username
            <input
              value={authUsername}
              onChange={(e) => setAuthUsername(e.target.value)}
              placeholder="yourname"
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={authPassword}
              onChange={(e) => setAuthPassword(e.target.value)}
              placeholder="8+ characters"
            />
          </label>
          {authError && <div className="auth-error">{authError}</div>}
          <div className="auth-actions">
            <button className="primary" onClick={handleStart} disabled={starting}>
              {starting ? 'Unlocking...' : 'Unlock'}
            </button>
          </div>
        </div>
        <div className="toasts">
          {toasts.map((toast) => (
            <div key={toast.id} className="toast">{toast.message}</div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="app">
      <aside className="sidebar">
        {/* <header className="brand">
          <div>
            <h1>p2pchat</h1>
            <p>{ready ? `Signed in as ${localUsername}` : 'Starting core...'}</p>
          </div>
          <div className={`signal ${ready ? 'on' : 'off'}`} />
        </header> */}
        <section className="section">
          <div className="section-title">Chats</div>
          <div className="chat-list">
            {chatList.length === 0 && <div className="empty">No chats yet</div>}
            {chatList.map((chat, index) => (
              <button
                key={chat.id}
                className={`chat-item ${selectedChat === chat.id ? 'active' : ''}`}
                style={{animationDelay: `${index * 40}ms`}}
                onClick={() => setSelectedChat(chat.id)}
              >
                <div>
                  <div className="chat-title">{chat.username || chat.id}</div>
                  <div className="chat-subtitle">
                    {chat.username ? chat.id : chat.lastMessage || 'No messages yet'}
                  </div>
                </div>
                <div className="chat-meta">
                  <span className={`status ${chat.connection || 'disconnected'}`}>{chat.connection || 'offline'}</span>
                  <span className={`status ${chat.status || 'pending'}`}>{chat.status || 'pending'}</span>
                </div>
              </button>
            ))}
          </div>
        </section>
        <div className="sidebar-footer">
          <button className="secondary" onClick={() => setMenuOpen(true)}>Menu</button>
        </div>
      </aside>

      <main className="main">
        <section className="chat-header">
          <div>
            <h2>{selectedChat ? (selectedMeta?.username || `Chat ${selectedChat}`) : 'Select a chat'}</h2>
            <p>Secure, direct, end-to-end</p>
          </div>
          <div className="header-actions">
            <button className="ghost" onClick={() => setMenuOpen(true)}>Menu</button>
          </div>
        </section>
        <section className="messages">
          {selectedChat ? (
            activeMessages.length === 0 ? (
              <div className="empty">No messages yet</div>
            ) : (
              activeMessages.map((msg, index) => (
                <div
                  key={msg.id}
                  className={`message ${msg.outgoing ? 'out' : 'in'}`}
                  style={{animationDelay: `${index * 30}ms`}}
                >
                  <div className="bubble">
                    <div className="body">{msg.body}</div>
                    <div className="meta">{formatTime(msg.tsMs)}</div>
                  </div>
                </div>
              ))
            )
          ) : (
            <div className="empty">Pick a peer to view messages</div>
          )}
        </section>
        <section className="composer">
          <input
            value={composer}
            onChange={(e) => setComposer(e.target.value)}
            placeholder={selectedChat ? 'Write a message' : 'Select a chat to send'}
            disabled={!selectedChat}
          />
          <button className="primary" onClick={handleSend} disabled={!selectedChat || !composer.trim()}>
            Send
          </button>
        </section>
      </main>

      {menuOpen && (
        <div className="menu-overlay" onClick={() => setMenuOpen(false)}>
          <div className="menu-panel" onClick={(e) => e.stopPropagation()}>
            {/* <div className="menu-header">
              <div>
                <h3>Menu</h3>
                <p>{ready ? `Signed in as ${localUsername}` : 'Starting core...'}</p>
              </div>
              <button className="ghost" onClick={() => setMenuOpen(false)}>Close</button>
            </div> */}

            <section className="menu-section">
              <div className="section-title">Profile</div>
              <div className="grid">
                <label>
                  Username
                  <input value={profileUsername} onChange={(e) => setProfileUsername(e.target.value)} />
                </label>
                <label>
                  New password
                  <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} />
                </label>
              </div>
              <div className="row">
                <button className="secondary" onClick={handleUpdateProfile}>Update profile</button>
              </div>
            </section>

            <section className="menu-section">
              <div className="section-title">Invite</div>
              <input
                value={inviteUsername}
                onChange={(e) => setInviteUsername(e.target.value)}
                placeholder="username"
              />
              <button className="primary" onClick={handleSendInvite}>Send invite</button>
            </section>

            <section className="menu-section">
              <div className="section-title">Invites</div>
              {incomingInvites.length === 0 && outgoingInvites.length === 0 && (
                <div className="empty">No invites</div>
              )}
              {incomingInvites.map((invite) => (
                <div key={invite.id} className="invite-item">
                  <div>
                    <div className="invite-title">@{invite.fromUsername}</div>
                    <div className="invite-subtitle">Incoming invite</div>
                  </div>
                  <div className="invite-actions">
                    <button className="secondary" onClick={() => handleAcceptInvite(invite)}>Accept</button>
                    <button className="ghost" onClick={() => handleDeclineInvite(invite)}>Decline</button>
                  </div>
                </div>
              ))}
              {outgoingInvites.map((invite) => (
                <div key={invite.id} className="invite-item">
                  <div>
                    <div className="invite-title">@{invite.toUsername}</div>
                    <div className="invite-subtitle">{invite.status}</div>
                  </div>
                </div>
              ))}
            </section>

            <section className="menu-section">
              <div className="section-title">Device Link</div>
              <div className="row">
                <button className="secondary" onClick={handleBeginLink}>Generate link code</button>
                <input value={linkCode} readOnly placeholder="Link code" />
              </div>
              <div className="row">
                <input value={linkInput} onChange={(e) => setLinkInput(e.target.value)} placeholder="Enter link code" />
                <button className="primary" onClick={handleLinkDevice}>Link device</button>
              </div>
            </section>

            <details className="menu-advanced">
              <summary>Advanced tools</summary>
              <div className="menu-advanced-body">
                <div className="section-title">Add Contact</div>
                <textarea
                  value={bundleHex}
                  onChange={(e) => setBundleHex(e.target.value)}
                  placeholder="Paste prekey bundle hex"
                />
                <input
                  value={contactUsername}
                  onChange={(e) => setContactUsername(e.target.value)}
                  placeholder="Username (optional)"
                />
                <button className="primary" onClick={handleAddContact}>Add Contact</button>

                <div className="section-title">Connect Peer</div>
                <input value={connectPeerId} onChange={(e) => setConnectPeerId(e.target.value)} placeholder="Peer id" />
                <div className="row">
                  <input value={connectAddress} onChange={(e) => setConnectAddress(e.target.value)} placeholder="Address" />
                  <input value={connectPort} onChange={(e) => setConnectPort(e.target.value)} placeholder="Port" />
                </div>
                <input value={connectIce} onChange={(e) => setConnectIce(e.target.value)} placeholder="ICE blob" />
                <button className="secondary" onClick={handleConnect}>Connect</button>
              </div>
            </details>
          </div>
        </div>
      )}

      <div className="toasts">
        {toasts.map((toast) => (
          <div key={toast.id} className="toast">{toast.message}</div>
        ))}
      </div>
    </div>
  );
}
