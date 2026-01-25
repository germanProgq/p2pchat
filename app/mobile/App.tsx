// Mobile chat UI for p2pchat. Spec: app.txt.
import React, {useCallback, useEffect, useMemo, useRef, useState} from 'react';
import {
  FlatList,
  LayoutAnimation,
  Modal,
  Platform,
  Pressable,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TextInput,
  UIManager,
  View,
  useWindowDimensions
} from 'react-native';
import Clipboard from '@react-native-clipboard/clipboard';
import RNFS from 'react-native-fs';
import {SafeAreaProvider, SafeAreaView} from 'react-native-safe-area-context';
import {Bridge, type HistoryMessage, type IncomingMessage, type NodeConfig} from './src/bridge';
import {SCHEMA_SQL} from './src/schema';
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
  sendInvite,
  setDirectoryUrl as setDirectoryBase
} from './src/directory';

type ContentType = 'text' | 'binary';

type ChatMeta = {
  id: string;
  username?: string;
  lastMessage?: string;
  lastTs?: number;
  connection?: string;
  status?: string;
  unread?: number;
};

type Message = {
  id: string;
  chatId: string;
  tsMs: number;
  contentType: ContentType;
  body: string;
  outgoing: boolean;
  pending?: boolean;
};

type TransportKind = 'quic' | 'webrtc' | 'loopback';

type UiConfig = {
  transportKind: TransportKind;
  bindAddress: string;
  bindPort: number;
  maxDatagramSize: number;
  maxInFlight: number;
  maxQueueBytes: number;
  retryBaseDelayMs: number;
  retryMaxDelayMs: number;
  retryMaxAttempts: number;
  retryJitterRatio: number;
  stunServers: string;
  oneTimePrekeys: number;
  signedPrekeyId: number;
  oneTimeStartId: number;
  handshakeBaseDelayMs: number;
  handshakeMaxDelayMs: number;
  handshakeMaxAttempts: number;
};

const DEFAULT_CONFIG: UiConfig = {
  transportKind: 'webrtc',
  bindAddress: '0.0.0.0',
  bindPort: 0,
  maxDatagramSize: 1200,
  maxInFlight: 32,
  maxQueueBytes: 1 << 20,
  retryBaseDelayMs: 100,
  retryMaxDelayMs: 2000,
  retryMaxAttempts: 5,
  retryJitterRatio: 0.2,
  stunServers: 'stun:stun.l.google.com:19302',
  oneTimePrekeys: 50,
  signedPrekeyId: 1,
  oneTimeStartId: 1000,
  handshakeBaseDelayMs: 200,
  handshakeMaxDelayMs: 2000,
  handshakeMaxAttempts: 5
};

const COLORS = {
  ink: '#151b22',
  muted: '#616772',
  accent: '#d46b2c',
  accentAlt: '#2f8f83',
  bg: '#f6f1ea',
  panel: '#ffffff',
  panelAlt: '#f2ece4',
  line: '#e2ddd5',
  danger: '#c9603b'
};

const FONT_BASE = Platform.select({ios: 'Avenir Next', android: 'sans-serif-condensed'}) || 'System';

const USERNAME_RE = /^[A-Za-z0-9._-]{3,32}$/;

const joinPath = (...parts: string[]) => parts.join('/').replace(/\/+/g, '/');

const bytesToHex = (value: ArrayBuffer) => {
  const bytes = new Uint8Array(value);
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
};

const hexToBytes = (hex: string) => {
  const cleaned = hex.replace(/[^a-fA-F0-9]/g, '');
  const length = cleaned.length - (cleaned.length % 2);
  const out = new Uint8Array(length / 2);
  for (let i = 0; i < length; i += 2) {
    out[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
  }
  return out;
};

const encodeUtf8 = (text: string) => {
  const encoded = unescape(encodeURIComponent(text));
  const out = new Uint8Array(encoded.length);
  for (let i = 0; i < encoded.length; i += 1) {
    out[i] = encoded.charCodeAt(i);
  }
  return out;
};

const decodeBody = (contentType: ContentType, body: any) => {
  if (contentType !== 'text') {
    if (typeof body === 'string') {
      return body;
    }
    if (Array.isArray(body)) {
      return `Binary (${body.length} bytes)`;
    }
    if (body instanceof ArrayBuffer) {
      return `Binary (${body.byteLength} bytes)`;
    }
    return 'Binary';
  }
  if (typeof body === 'string') {
    return body;
  }
  const bytes = Array.isArray(body) ? Uint8Array.from(body) : new Uint8Array(body);
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += String.fromCharCode(bytes[i]);
  }
  return out;
};

const formatTime = (tsMs: number) => {
  const date = new Date(tsMs);
  return date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
};

const animateNext = () => {
  LayoutAnimation.configureNext({
    duration: 180,
    create: {type: LayoutAnimation.Types.easeInEaseOut, property: LayoutAnimation.Properties.opacity},
    update: {type: LayoutAnimation.Types.easeInEaseOut},
    delete: {type: LayoutAnimation.Types.easeInEaseOut, property: LayoutAnimation.Properties.opacity}
  });
};

const isValidUsername = (username: string) => USERNAME_RE.test(username);

const isValidPassword = (password: string) => password.length >= 8 && password.length <= 128;

const mergeInvites = (prev: DirectoryInvite[], incoming: DirectoryInvite[]) => {
  const map = new Map(prev.map((invite) => [invite.id, invite]));
  for (const invite of incoming) {
    const existing = map.get(invite.id);
    map.set(invite.id, existing ? {...existing, ...invite} : invite);
  }
  return Array.from(map.values()).sort((a, b) => b.updatedAtMs - a.updatedAtMs);
};

export default function App() {
  const [ready, setReady] = useState(false);
  const [starting, setStarting] = useState(false);
  const [config, setConfig] = useState<UiConfig>(DEFAULT_CONFIG);
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [sessionPassword, setSessionPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);
  const [directoryUrl, setDirectoryUrlState] = useState('http://localhost:8787');
  const [localUsername, setLocalUsername] = useState('');
  const [profileUsername, setProfileUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [invitesVisible, setInvitesVisible] = useState(false);
  const [inviteUsername, setInviteUsername] = useState('');
  const [invites, setInvites] = useState<DirectoryInvite[]>([]);
  const [lastInviteSync, setLastInviteSync] = useState(0);
  const processedInvites = useRef<Set<string>>(new Set());
  const [chats, setChats] = useState<Record<string, ChatMeta>>({});
  const [messages, setMessages] = useState<Record<string, Message[]>>({});
  const [selectedChat, setSelectedChat] = useState<string | null>(null);
  const [composer, setComposer] = useState('');
  const [bundleHex, setBundleHex] = useState('');
  const [contactUsername, setContactUsername] = useState('');
  const [localBundleHex, setLocalBundleHex] = useState('');
  const [localIce, setLocalIce] = useState('');
  const [linkCode, setLinkCode] = useState('');
  const [linkInput, setLinkInput] = useState('');
  const [connectPeerId, setConnectPeerId] = useState('');
  const [connectAddress, setConnectAddress] = useState('');
  const [connectPort, setConnectPort] = useState('');
  const [connectIce, setConnectIce] = useState('');
  const [settingsVisible, setSettingsVisible] = useState(false);
  const [linkVisible, setLinkVisible] = useState(false);
  const [localVisible, setLocalVisible] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const messageListRef = useRef<FlatList<Message> | null>(null);
  const {width} = useWindowDimensions();
  const isWide = width >= 960;

  const effectiveUsername = localUsername || authUsername.trim();

  useEffect(() => {
    if (Platform.OS === 'android' && UIManager.setLayoutAnimationEnabledExperimental) {
      UIManager.setLayoutAnimationEnabledExperimental(true);
    }
  }, []);

  useEffect(() => {
    setDirectoryBase(directoryUrl);
  }, [directoryUrl]);

  const chatList = useMemo(() => {
    return Object.values(chats).sort((a, b) => (b.lastTs || 0) - (a.lastTs || 0));
  }, [chats]);

  const activeMessages = selectedChat ? messages[selectedChat] || [] : [];

  const incomingInvites = useMemo(() => {
    return invites.filter((invite) => invite.toUsername === effectiveUsername && invite.status === 'pending');
  }, [effectiveUsername, invites]);

  const outgoingInvites = useMemo(() => {
    return invites.filter((invite) => invite.fromUsername === effectiveUsername);
  }, [effectiveUsername, invites]);

  const showToast = useCallback((message: string) => {
    setToast(message);
    setTimeout(() => setToast(null), 3500);
  }, []);

  const ensureCoreFiles = useCallback(async () => {
    const baseDir = joinPath(RNFS.DocumentDirectoryPath, 'p2pchat');
    const schemaPath = joinPath(baseDir, 'schema.sql');
    const configPath = joinPath(baseDir, 'config.json');
    await RNFS.mkdir(baseDir);
    if (!(await RNFS.exists(schemaPath))) {
      await RNFS.writeFile(schemaPath, SCHEMA_SQL, 'utf8');
    }
    return {
      dataDir: baseDir,
      identityPath: joinPath(baseDir, 'identity.bin'),
      storagePath: joinPath(baseDir, 'store.db'),
      schemaPath,
      configPath
    };
  }, []);

  const loadStoredConfig = useCallback(async () => {
    try {
      const paths = await ensureCoreFiles();
      if (await RNFS.exists(paths.configPath)) {
        const raw = await RNFS.readFile(paths.configPath, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed.config) {
          setConfig({...DEFAULT_CONFIG, ...parsed.config});
        }
        if (typeof parsed.username === 'string') {
          setAuthUsername(parsed.username);
        }
        if (typeof parsed.directoryUrl === 'string') {
          setDirectoryUrlState(parsed.directoryUrl);
        }
      }
    } catch (err) {
      showToast(String(err));
    }
  }, [ensureCoreFiles, showToast]);

  const saveStoredConfig = useCallback(async (nextConfig: UiConfig, username: string, dirUrl: string) => {
    const paths = await ensureCoreFiles();
    const payload = JSON.stringify({config: nextConfig, username, directoryUrl: dirUrl});
    await RNFS.writeFile(paths.configPath, payload, 'utf8');
  }, [ensureCoreFiles]);

  useEffect(() => {
    loadStoredConfig();
  }, [loadStoredConfig]);

  const buildNodeConfig = useCallback(async (username: string, password: string): Promise<NodeConfig> => {
    const paths = await ensureCoreFiles();
    const stunServers = config.stunServers
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
    const base = {
      identityPath: paths.identityPath,
      storagePath: paths.storagePath,
      schemaPath: paths.schemaPath,
      username,
      password,
      transportKind: config.transportKind,
      transport: {
        maxInFlight: config.maxInFlight,
        maxQueueBytes: config.maxQueueBytes,
        retry: {
          baseDelayMs: config.retryBaseDelayMs,
          maxDelayMs: config.retryMaxDelayMs,
          maxAttempts: config.retryMaxAttempts,
          jitterRatio: config.retryJitterRatio
        }
      },
      quic: {
        bindAddress: config.bindAddress,
        bindPort: config.bindPort,
        maxDatagramSize: config.maxDatagramSize,
        ice: {stunServers}
      },
      webrtc: {
        bindAddress: config.bindAddress,
        bindPort: config.bindPort,
        maxDatagramSize: config.maxDatagramSize,
        ice: {stunServers}
      },
      oneTimePrekeys: config.oneTimePrekeys,
      signedPrekeyId: config.signedPrekeyId,
      oneTimeStartId: config.oneTimeStartId,
      handshakeBaseDelayMs: config.handshakeBaseDelayMs,
      handshakeMaxDelayMs: config.handshakeMaxDelayMs,
      handshakeMaxAttempts: config.handshakeMaxAttempts
    };
    return base;
  }, [config, ensureCoreFiles]);

  const refreshLocalInfo = useCallback(() => {
    try {
      const bundle = Bridge.localBundle();
      const ice = Bridge.localIce();
      setLocalBundleHex(bytesToHex(bundle));
      setLocalIce(ice);
    } catch (err) {
      showToast(String(err));
    }
  }, [showToast]);

  const signMessageHex = useCallback((message: string) => {
    const bytes = encodeUtf8(message);
    const signature = Bridge.signIdentity(bytes.buffer);
    return bytesToHex(signature);
  }, []);

  const claimDirectoryUsername = useCallback(async (username: string) => {
    const identityKey = bytesToHex(Bridge.localIdentityPublicKey());
    const challenge = await requestChallenge(username, identityKey);
    const message = buildClaimMessage(username, challenge.nonce);
    const signatureHex = signMessageHex(message);
    await claimUsername({
      username,
      identityKeyHex: identityKey,
      challengeId: challenge.challengeId,
      signatureHex,
      bundleHex: bytesToHex(Bridge.localBundle()),
      ice: Bridge.localIce()
    });
  }, [signMessageHex]);

  const handleUnlock = useCallback(async () => {
    if (starting) {
      return;
    }
    setStarting(true);
    setAuthError(null);
    const username = authUsername.trim();
    const password = authPassword || sessionPassword;
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
    try {
      const nodeConfig = await buildNodeConfig(username, password);
      Bridge.start(nodeConfig);
      setReady(true);
      setLocalUsername(username);
      setProfileUsername(username);
      setSessionPassword(password);
      setAuthPassword('');
      refreshLocalInfo();
      await saveStoredConfig(config, username, directoryUrl);
      try {
        await claimDirectoryUsername(username);
      } catch (err) {
        showToast(`Directory claim failed: ${String(err)}`);
      }
    } catch (err) {
      showToast(String(err));
      setReady(false);
    } finally {
      setStarting(false);
    }
  }, [authPassword, authUsername, buildNodeConfig, claimDirectoryUsername, config, directoryUrl, refreshLocalInfo, saveStoredConfig, sessionPassword, showToast, starting]);

  const handleUpdateProfile = useCallback(async () => {
    if (!ready) {
      return;
    }
    const nextUsername = profileUsername.trim();
    const passwordUpdate = newPassword.trim();
    if (nextUsername && !isValidUsername(nextUsername)) {
      showToast('Username must be 3-32 chars of letters, numbers, ., -, _');
      return;
    }
    if (passwordUpdate && !isValidPassword(passwordUpdate)) {
      showToast('Password must be 8-128 characters');
      return;
    }
    try {
      if (nextUsername && nextUsername !== localUsername) {
        await claimDirectoryUsername(nextUsername);
      }
      Bridge.updateProfile(nextUsername === localUsername ? '' : nextUsername, passwordUpdate);
      let persistedUsername = localUsername;
      if (nextUsername && nextUsername !== localUsername) {
        setLocalUsername(nextUsername);
        setAuthUsername(nextUsername);
        setProfileUsername(nextUsername);
        persistedUsername = nextUsername;
      }
      if (passwordUpdate) {
        setSessionPassword(passwordUpdate);
        setNewPassword('');
      }
      await saveStoredConfig(config, persistedUsername, directoryUrl);
      showToast('Profile updated');
    } catch (err) {
      showToast(String(err));
    }
  }, [claimDirectoryUsername, config, directoryUrl, localUsername, newPassword, profileUsername, ready, saveStoredConfig, showToast]);

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
            const bundleBytes = hexToBytes(invite.toBundleHex);
            const peerId = Bridge.addContactWithUsername(bundleBytes.buffer, invite.toUsername);
            setChats((prev) => ({
              ...prev,
              [peerId]: {id: peerId, username: invite.toUsername, lastMessage: 'Invite accepted'}
            }));
            if (invite.toIce) {
              Bridge.connectPeer({peerId, iceBlob: invite.toIce});
            }
          } catch (err) {
            processedInvites.current.delete(invite.id);
            showToast(String(err));
          }
        }
      }
    } catch (err) {
      showToast(String(err));
    }
  }, [effectiveUsername, lastInviteSync, showToast]);

  const handleSendInvite = useCallback(async () => {
    const toUsername = inviteUsername.trim();
    if (!effectiveUsername) {
      showToast('Unlock the app first');
      return;
    }
    if (!toUsername) {
      showToast('Username required');
      return;
    }
    if (toUsername === effectiveUsername) {
      showToast('Cannot invite yourself');
      return;
    }
    try {
      const bundleHex = bytesToHex(Bridge.localBundle());
      const ice = Bridge.localIce();
      const timestampMs = Date.now();
      const message = buildInviteMessage({
        fromUsername: effectiveUsername,
        toUsername,
        fromBundleHex: bundleHex,
        fromIce: ice,
        timestampMs
      });
      const signatureHex = signMessageHex(message);
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
      showToast(String(err));
    }
  }, [effectiveUsername, inviteUsername, showToast, signMessageHex]);

  const handleAcceptInvite = useCallback(async (invite: DirectoryInvite) => {
    if (!effectiveUsername) {
      return;
    }
    try {
      const bundleHex = bytesToHex(Bridge.localBundle());
      const ice = Bridge.localIce();
      const timestampMs = Date.now();
      const message = buildInviteAcceptMessage({
        inviteId: invite.id,
        username: effectiveUsername,
        bundleHex,
        ice,
        timestampMs
      });
      const signatureHex = signMessageHex(message);
      const updated = await acceptInvite({
        inviteId: invite.id,
        username: effectiveUsername,
        bundleHex,
        ice,
        signatureHex,
        timestampMs
      });
      setInvites((prev) => mergeInvites(prev, [updated]));
      const bundleBytes = hexToBytes(invite.fromBundleHex);
      const peerId = Bridge.addContactWithUsername(bundleBytes.buffer, invite.fromUsername);
      setChats((prev) => ({
        ...prev,
        [peerId]: {id: peerId, username: invite.fromUsername, lastMessage: 'Invite accepted'}
      }));
      setSelectedChat(peerId);
      if (invite.fromIce) {
        Bridge.connectPeer({peerId, iceBlob: invite.fromIce});
      }
      processedInvites.current.add(invite.id);
    } catch (err) {
      showToast(String(err));
    }
  }, [effectiveUsername, showToast, signMessageHex]);

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
      const signatureHex = signMessageHex(message);
      const updated = await declineInvite({
        inviteId: invite.id,
        username: effectiveUsername,
        signatureHex,
        timestampMs
      });
      setInvites((prev) => mergeInvites(prev, [updated]));
    } catch (err) {
      showToast(String(err));
    }
  }, [effectiveUsername, showToast, signMessageHex]);

  const handleIncoming = useCallback((msg: IncomingMessage) => {
    animateNext();
    const contentType = msg.contentType as ContentType;
    const body = decodeBody(contentType, msg.body);
    const message: Message = {
      id: msg.msgId,
      chatId: msg.chatId,
      tsMs: msg.tsMs,
      contentType,
      body,
      outgoing: false
    };
    setMessages((prev) => ({
      ...prev,
      [msg.chatId]: [...(prev[msg.chatId] || []), message]
    }));
    setChats((prev) => {
      const existing = prev[msg.chatId] || {id: msg.chatId};
      return {
        ...prev,
        [msg.chatId]: {
          ...existing,
          username: msg.peerUsername || existing.username,
          lastMessage: body,
          lastTs: msg.tsMs,
          unread: selectedChat === msg.chatId ? 0 : (existing.unread || 0) + 1
        }
      };
    });
  }, [selectedChat]);

  const handleHistory = useCallback((history: HistoryMessage[]) => {
    if (!selectedChat) {
      return;
    }
    const mapped: Message[] = history.map((entry) => {
      const contentType = entry.contentType as ContentType;
      return {
        id: entry.msgId,
        chatId: entry.chatId,
        tsMs: entry.tsMs,
        contentType,
        body: decodeBody(contentType, entry.body),
        outgoing: entry.senderDevice !== entry.chatId
      };
    });
    setMessages((prev) => ({
      ...prev,
      [selectedChat]: mapped
    }));
    const peerUsername = history.find((entry) => entry.peerUsername)?.peerUsername;
    if (peerUsername) {
      setChats((prev) => ({
        ...prev,
        [selectedChat]: {
          ...(prev[selectedChat] || {id: selectedChat}),
          username: peerUsername
        }
      }));
    }
  }, [selectedChat]);

  const handleSend = useCallback(async () => {
    if (!selectedChat || !composer.trim()) {
      return;
    }
    const text = composer.trim();
    setComposer('');
    animateNext();
    const localMessage: Message = {
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
      [selectedChat]: [...(prev[selectedChat] || []), localMessage]
    }));
    setChats((prev) => ({
      ...prev,
      [selectedChat]: {
        ...(prev[selectedChat] || {id: selectedChat}),
        lastMessage: text,
        lastTs: localMessage.tsMs
      }
    }));
    try {
      Bridge.send(selectedChat, text);
    } catch (err) {
      showToast(String(err));
    }
  }, [composer, selectedChat, showToast]);

  const handleAddContact = useCallback(() => {
    const cleaned = bundleHex.trim();
    if (!cleaned) {
      showToast('Paste a prekey bundle');
      return;
    }
    const bytes = hexToBytes(cleaned);
    if (bytes.length === 0) {
      showToast('Invalid bundle format');
      return;
    }
    try {
      const username = contactUsername.trim();
      const peerId = username
        ? Bridge.addContactWithUsername(bytes.buffer, username)
        : Bridge.addContact(bytes.buffer);
      animateNext();
      setChats((prev) => ({
        ...prev,
        [peerId]: {id: peerId, username: username || prev[peerId]?.username, lastMessage: 'Contact added', lastTs: Date.now()}
      }));
      setBundleHex('');
      setContactUsername('');
      setSelectedChat(peerId);
    } catch (err) {
      showToast(String(err));
    }
  }, [bundleHex, contactUsername, showToast]);

  const handleConnect = useCallback(() => {
    if (!connectPeerId.trim()) {
      showToast('Peer id required');
      return;
    }
    const port = connectPort.trim() ? Number(connectPort) : undefined;
    try {
      Bridge.connectPeer({
        peerId: connectPeerId.trim(),
        address: connectAddress.trim() ? connectAddress.trim() : undefined,
        port: port && !Number.isNaN(port) ? port : undefined,
        iceBlob: connectIce.trim() ? connectIce.trim() : undefined
      });
      setConnectAddress('');
      setConnectPort('');
      setConnectIce('');
    } catch (err) {
      showToast(String(err));
    }
  }, [connectAddress, connectIce, connectPeerId, connectPort, showToast]);

  const handleBeginLink = useCallback(() => {
    try {
      const code = Bridge.beginLink();
      setLinkCode(code);
    } catch (err) {
      showToast(String(err));
    }
  }, [showToast]);

  const handleLinkDevice = useCallback(() => {
    if (!linkInput.trim()) {
      showToast('Link code required');
      return;
    }
    try {
      Bridge.linkDevice(linkInput.trim());
      setLinkInput('');
    } catch (err) {
      showToast(String(err));
    }
  }, [linkInput, showToast]);

  useEffect(() => {
    if (!ready) {
      return;
    }
    const subs = [
      Bridge.onMessage(handleIncoming),
      Bridge.onConnectionChange((event) => {
        const peerId = event.peerId as string;
        setChats((prev) => ({
          ...prev,
          [peerId]: {
            ...(prev[peerId] || {id: peerId}),
            username: event.peerUsername || prev[peerId]?.username,
            connection: event.state
          }
        }));
      }),
      Bridge.onPeerStatus((event) => {
        const peerId = event.peerId as string;
        setChats((prev) => ({
          ...prev,
          [peerId]: {
            ...(prev[peerId] || {id: peerId}),
            username: event.peerUsername || prev[peerId]?.username,
            status: event.status
          }
        }));
      }),
      Bridge.onError((event) => {
        showToast(event.message || 'Core error');
      })
    ];
    return () => subs.forEach((sub) => sub.remove());
  }, [handleIncoming, ready, showToast]);

  useEffect(() => {
    if (!ready) {
      return;
    }
    const interval = setInterval(() => {
      refreshInvites();
    }, 5000);
    refreshInvites();
    return () => clearInterval(interval);
  }, [ready, refreshInvites]);

  useEffect(() => {
    if (!selectedChat) {
      return;
    }
    try {
      const history = Bridge.getHistory(selectedChat, 1, 200);
      handleHistory(history as HistoryMessage[]);
      setChats((prev) => ({
        ...prev,
        [selectedChat]: {
          ...(prev[selectedChat] || {id: selectedChat}),
          unread: 0
        }
      }));
    } catch (err) {
      showToast(String(err));
    }
  }, [handleHistory, selectedChat, showToast]);

  useEffect(() => {
    if (activeMessages.length === 0) {
      return;
    }
    const timer = setTimeout(() => {
      messageListRef.current?.scrollToEnd({animated: true});
    }, 120);
    return () => clearTimeout(timer);
  }, [activeMessages]);

  const renderChatItem = useCallback(({item}: {item: ChatMeta}) => {
    const isActive = item.id === selectedChat;
    return (
      <Pressable
        onPress={() => setSelectedChat(item.id)}
        style={({pressed}) => [
          styles.chatItem,
          isActive && styles.chatItemActive,
          pressed && styles.chatItemPressed
        ]}
      >
        <View style={styles.chatItemBody}>
          <Text style={styles.chatTitle} numberOfLines={1}>{item.username || item.id}</Text>
          <Text style={styles.chatSubtitle} numberOfLines={1}>{item.username ? item.id : item.lastMessage || 'No messages yet'}</Text>
        </View>
        <View style={styles.chatMeta}>
          <Text style={[styles.chatStatus, item.connection === 'connected' && styles.chatStatusActive]}>{item.connection || 'offline'}</Text>
          <Text style={[styles.chatStatus, item.status === 'ready' && styles.chatStatusReady]}>{item.status || 'pending'}</Text>
          {!!item.unread && <View style={styles.unreadPill}><Text style={styles.unreadText}>{item.unread}</Text></View>}
        </View>
      </Pressable>
    );
  }, [selectedChat]);

  const renderMessageItem = useCallback(({item}: {item: Message}) => {
    return (
      <View style={[styles.messageRow, item.outgoing ? styles.messageRowOut : styles.messageRowIn]}>
        <View style={[styles.messageBubble, item.outgoing ? styles.messageBubbleOut : styles.messageBubbleIn]}>
          <Text style={styles.messageText}>{item.body}</Text>
          <Text style={styles.messageMeta}>{formatTime(item.tsMs)}{item.pending ? ' · sending' : ''}</Text>
        </View>
      </View>
    );
  }, []);

  const listContent = (
    <ScrollView contentContainerStyle={styles.sidebarContent}>
      {/* <View style={styles.brandRow}>
        <View>
          <Text style={styles.brandTitle}>p2pchat</Text>
          <Text style={styles.brandSubtitle}>{ready ? `Signed in as ${localUsername}` : 'Starting core'}</Text>
        </View>
        <View style={[styles.statusDot, ready ? styles.statusDotOn : styles.statusDotOff]} />
      </View> */}

      <View style={styles.actionRow}>
        <Pressable style={styles.actionButton} onPress={() => setSettingsVisible(true)}>
          <Text style={styles.actionButtonText}>Settings</Text>
        </Pressable>
        <Pressable style={styles.actionButton} onPress={() => setInvitesVisible(true)}>
          <Text style={styles.actionButtonText}>Invites</Text>
        </Pressable>
        <Pressable style={styles.actionButton} onPress={() => setLinkVisible(true)}>
          <Text style={styles.actionButtonText}>Link</Text>
        </Pressable>
        <Pressable style={styles.actionButton} onPress={() => setLocalVisible(true)}>
          <Text style={styles.actionButtonText}>Local</Text>
        </Pressable>
      </View>

      <Text style={styles.sectionTitle}>Chats</Text>
      {chatList.length === 0 ? (
        <Text style={styles.emptyText}>No chats yet</Text>
      ) : (
        <FlatList
          data={chatList}
          keyExtractor={(item) => item.id}
          renderItem={renderChatItem}
          scrollEnabled={false}
        />
      )}

      <Text style={styles.sectionTitle}>Add Contact</Text>
      <TextInput
        value={bundleHex}
        onChangeText={setBundleHex}
        placeholder="Paste prekey bundle hex"
        placeholderTextColor={COLORS.muted}
        multiline
        style={styles.inputMulti}
      />
      <TextInput
        value={contactUsername}
        onChangeText={setContactUsername}
        placeholder="Username (optional)"
        placeholderTextColor={COLORS.muted}
        style={styles.input}
      />
      <Pressable style={styles.primaryButton} onPress={handleAddContact}>
        <Text style={styles.primaryButtonText}>Add Contact</Text>
      </Pressable>

      <Text style={styles.sectionTitle}>Connect Peer</Text>
      <TextInput
        value={connectPeerId}
        onChangeText={setConnectPeerId}
        placeholder="Peer id"
        placeholderTextColor={COLORS.muted}
        style={styles.input}
      />
      <View style={styles.row}>
        <TextInput
          value={connectAddress}
          onChangeText={setConnectAddress}
          placeholder="Address"
          placeholderTextColor={COLORS.muted}
          style={[styles.input, styles.rowInput]}
        />
        <TextInput
          value={connectPort}
          onChangeText={setConnectPort}
          placeholder="Port"
          placeholderTextColor={COLORS.muted}
          keyboardType="numeric"
          style={[styles.input, styles.rowInput]}
        />
      </View>
      <TextInput
        value={connectIce}
        onChangeText={setConnectIce}
        placeholder="ICE blob"
        placeholderTextColor={COLORS.muted}
        style={styles.input}
      />
      <Pressable style={styles.secondaryButton} onPress={handleConnect}>
        <Text style={styles.secondaryButtonText}>Connect</Text>
      </Pressable>
    </ScrollView>
  );

  const chatContent = (
    <View style={styles.chatPane}>
      <View style={styles.chatHeader}>
        {!isWide && (
          <Pressable style={styles.backButton} onPress={() => setSelectedChat(null)}>
            <Text style={styles.backButtonText}>Back</Text>
          </Pressable>
        )}
        <View>
          <Text style={styles.chatHeaderTitle}>
            {selectedChat ? chats[selectedChat]?.username || `Chat ${selectedChat}` : 'Select a chat'}
          </Text>
          <Text style={styles.chatHeaderSubtitle}>Secure, direct, end-to-end</Text>
        </View>
        <View style={styles.headerActions}>
          <Pressable style={styles.ghostButton} onPress={refreshLocalInfo}>
            <Text style={styles.ghostButtonText}>Refresh</Text>
          </Pressable>
        </View>
      </View>

      {selectedChat ? (
        <FlatList
          ref={(ref) => { messageListRef.current = ref; }}
          data={activeMessages}
          keyExtractor={(item) => item.id}
          renderItem={renderMessageItem}
          contentContainerStyle={styles.messageList}
        />
      ) : (
        <View style={styles.emptyPane}>
          <Text style={styles.emptyText}>Pick a peer to view messages</Text>
        </View>
      )}

      <View style={styles.composer}>
        <TextInput
          value={composer}
          onChangeText={setComposer}
          placeholder={selectedChat ? 'Write a message' : 'Select a chat to send'}
          placeholderTextColor={COLORS.muted}
          editable={!!selectedChat}
          style={[styles.input, styles.composerInput]}
        />
        <Pressable style={[styles.primaryButton, !composer.trim() && styles.buttonDisabled]} onPress={handleSend}>
          <Text style={styles.primaryButtonText}>Send</Text>
        </Pressable>
      </View>
    </View>
  );

  if (!ready) {
    return (
      <SafeAreaProvider>
        <SafeAreaView style={styles.safeArea}>
          <StatusBar barStyle="dark-content" />
          <View style={styles.authScreen}>
            <View style={styles.authCard}>
              <Text style={styles.authTitle}>p2pchat</Text>
              <Text style={styles.authSubtitle}>Unlock your identity</Text>
              <TextInput
                value={authUsername}
                onChangeText={setAuthUsername}
                placeholder="Username"
                placeholderTextColor={COLORS.muted}
                style={styles.input}
                autoCapitalize="none"
              />
              <TextInput
                value={authPassword}
                onChangeText={setAuthPassword}
                placeholder="Password"
                placeholderTextColor={COLORS.muted}
                style={styles.input}
                secureTextEntry
              />
              <TextInput
                value={directoryUrl}
                onChangeText={setDirectoryUrlState}
                placeholder="Directory URL"
                placeholderTextColor={COLORS.muted}
                style={styles.input}
                autoCapitalize="none"
              />
              {authError ? <Text style={styles.authError}>{authError}</Text> : null}
              <Pressable style={styles.primaryButton} onPress={handleUnlock}>
                <Text style={styles.primaryButtonText}>{starting ? 'Unlocking...' : 'Unlock'}</Text>
              </Pressable>
            </View>
          </View>
          {toast ? (
            <View style={styles.toast}>
              <Text style={styles.toastText}>{toast}</Text>
            </View>
          ) : null}
        </SafeAreaView>
      </SafeAreaProvider>
    );
  }

  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.safeArea}>
        <StatusBar barStyle="dark-content" />
        <View style={[styles.app, isWide && styles.appWide]}>
          {isWide ? (
            <>
              <View style={styles.sidebar}>{listContent}</View>
              <View style={styles.main}>{chatContent}</View>
            </>
          ) : (
            <View style={styles.main}>{selectedChat ? chatContent : listContent}</View>
          )}
        </View>

        <Modal visible={settingsVisible} animationType="slide" onRequestClose={() => setSettingsVisible(false)}>
          <SafeAreaView style={styles.modalRoot}>
            <ScrollView contentContainerStyle={styles.modalContent}>
              <View style={styles.modalHeader}>
                <Text style={styles.modalTitle}>Settings</Text>
                <Pressable style={styles.ghostButton} onPress={() => setSettingsVisible(false)}>
                  <Text style={styles.ghostButtonText}>Close</Text>
                </Pressable>
              </View>

              <Text style={styles.sectionTitle}>Profile</Text>
              <View style={styles.row}>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Username</Text>
                  <TextInput value={profileUsername} onChangeText={setProfileUsername} style={styles.input} />
                </View>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>New password</Text>
                  <TextInput value={newPassword} onChangeText={setNewPassword} secureTextEntry style={styles.input} />
                </View>
              </View>
              <View style={styles.field}>
                <Text style={styles.fieldLabel}>Directory URL</Text>
                <TextInput value={directoryUrl} onChangeText={setDirectoryUrlState} style={styles.input} />
              </View>
              <Pressable style={styles.secondaryButton} onPress={handleUpdateProfile}>
                <Text style={styles.secondaryButtonText}>Update profile</Text>
              </Pressable>

              <Text style={styles.sectionTitle}>Transport</Text>
              <View style={styles.row}>
                {(['webrtc', 'quic', 'loopback'] as TransportKind[]).map((kind) => (
                  <Pressable
                    key={kind}
                    onPress={() => setConfig((prev) => ({...prev, transportKind: kind}))}
                    style={[styles.choiceButton, config.transportKind === kind && styles.choiceButtonActive]}
                  >
                    <Text style={[styles.choiceButtonText, config.transportKind === kind && styles.choiceButtonTextActive]}>
                      {kind.toUpperCase()}
                    </Text>
                  </Pressable>
                ))}
              </View>

              <View style={styles.row}>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Bind address</Text>
                  <TextInput value={config.bindAddress} onChangeText={(text) => setConfig((prev) => ({...prev, bindAddress: text}))} style={styles.input} />
                </View>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Bind port</Text>
                  <TextInput value={String(config.bindPort)} onChangeText={(text) => setConfig((prev) => ({...prev, bindPort: Number(text) || 0}))} keyboardType="numeric" style={styles.input} />
                </View>
              </View>

              <View style={styles.row}>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Datagram size</Text>
                  <TextInput value={String(config.maxDatagramSize)} onChangeText={(text) => setConfig((prev) => ({...prev, maxDatagramSize: Number(text) || 1200}))} keyboardType="numeric" style={styles.input} />
                </View>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Max in-flight</Text>
                  <TextInput value={String(config.maxInFlight)} onChangeText={(text) => setConfig((prev) => ({...prev, maxInFlight: Number(text) || 32}))} keyboardType="numeric" style={styles.input} />
                </View>
              </View>

              <View style={styles.field}>
                <Text style={styles.fieldLabel}>STUN servers (one per line)</Text>
                <TextInput
                  value={config.stunServers}
                  onChangeText={(text) => setConfig((prev) => ({...prev, stunServers: text}))}
                  style={styles.inputMulti}
                  multiline
                />
              </View>

              <View style={styles.row}>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Retry base (ms)</Text>
                  <TextInput value={String(config.retryBaseDelayMs)} onChangeText={(text) => setConfig((prev) => ({...prev, retryBaseDelayMs: Number(text) || 100}))} keyboardType="numeric" style={styles.input} />
                </View>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Retry max (ms)</Text>
                  <TextInput value={String(config.retryMaxDelayMs)} onChangeText={(text) => setConfig((prev) => ({...prev, retryMaxDelayMs: Number(text) || 2000}))} keyboardType="numeric" style={styles.input} />
                </View>
              </View>

              <View style={styles.row}>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Retry attempts</Text>
                  <TextInput value={String(config.retryMaxAttempts)} onChangeText={(text) => setConfig((prev) => ({...prev, retryMaxAttempts: Number(text) || 5}))} keyboardType="numeric" style={styles.input} />
                </View>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Retry jitter</Text>
                  <TextInput value={String(config.retryJitterRatio)} onChangeText={(text) => setConfig((prev) => ({...prev, retryJitterRatio: Number(text) || 0.2}))} keyboardType="decimal-pad" style={styles.input} />
                </View>
              </View>

              <View style={styles.row}>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Handshake base (ms)</Text>
                  <TextInput value={String(config.handshakeBaseDelayMs)} onChangeText={(text) => setConfig((prev) => ({...prev, handshakeBaseDelayMs: Number(text) || 200}))} keyboardType="numeric" style={styles.input} />
                </View>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Handshake max (ms)</Text>
                  <TextInput value={String(config.handshakeMaxDelayMs)} onChangeText={(text) => setConfig((prev) => ({...prev, handshakeMaxDelayMs: Number(text) || 2000}))} keyboardType="numeric" style={styles.input} />
                </View>
              </View>

              <View style={styles.row}>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>Handshake attempts</Text>
                  <TextInput value={String(config.handshakeMaxAttempts)} onChangeText={(text) => setConfig((prev) => ({...prev, handshakeMaxAttempts: Number(text) || 5}))} keyboardType="numeric" style={styles.input} />
                </View>
                <View style={styles.field}>
                  <Text style={styles.fieldLabel}>One-time prekeys</Text>
                  <TextInput value={String(config.oneTimePrekeys)} onChangeText={(text) => setConfig((prev) => ({...prev, oneTimePrekeys: Number(text) || 50}))} keyboardType="numeric" style={styles.input} />
                </View>
              </View>

              <Pressable style={styles.primaryButton} onPress={handleUnlock}>
                <Text style={styles.primaryButtonText}>Restart core</Text>
              </Pressable>
            </ScrollView>
          </SafeAreaView>
        </Modal>

        <Modal visible={invitesVisible} animationType="slide" onRequestClose={() => setInvitesVisible(false)}>
          <SafeAreaView style={styles.modalRoot}>
            <ScrollView contentContainerStyle={styles.modalContent}>
              <View style={styles.modalHeader}>
                <Text style={styles.modalTitle}>Invites</Text>
                <Pressable style={styles.ghostButton} onPress={() => setInvitesVisible(false)}>
                  <Text style={styles.ghostButtonText}>Close</Text>
                </Pressable>
              </View>

              <Text style={styles.sectionTitle}>Send invite</Text>
              <View style={styles.row}>
                <TextInput
                  value={inviteUsername}
                  onChangeText={setInviteUsername}
                  placeholder="Username"
                  placeholderTextColor={COLORS.muted}
                  style={[styles.input, styles.rowInput]}
                  autoCapitalize="none"
                />
                <Pressable style={styles.primaryButton} onPress={handleSendInvite}>
                  <Text style={styles.primaryButtonText}>Send</Text>
                </Pressable>
              </View>

              <Text style={styles.sectionTitle}>Incoming</Text>
              {incomingInvites.length === 0 ? (
                <Text style={styles.emptyText}>No incoming invites</Text>
              ) : (
                incomingInvites.map((invite) => (
                  <View key={invite.id} style={styles.inviteCard}>
                    <View>
                      <Text style={styles.inviteTitle}>@{invite.fromUsername}</Text>
                      <Text style={styles.inviteSubtitle}>Incoming invite</Text>
                    </View>
                    <View style={styles.inviteActions}>
                      <Pressable style={styles.secondaryButton} onPress={() => handleAcceptInvite(invite)}>
                        <Text style={styles.secondaryButtonText}>Accept</Text>
                      </Pressable>
                      <Pressable style={styles.ghostButton} onPress={() => handleDeclineInvite(invite)}>
                        <Text style={styles.ghostButtonText}>Decline</Text>
                      </Pressable>
                    </View>
                  </View>
                ))
              )}

              <Text style={styles.sectionTitle}>Outgoing</Text>
              {outgoingInvites.length === 0 ? (
                <Text style={styles.emptyText}>No outgoing invites</Text>
              ) : (
                outgoingInvites.map((invite) => (
                  <View key={invite.id} style={styles.inviteCard}>
                    <View>
                      <Text style={styles.inviteTitle}>@{invite.toUsername}</Text>
                      <Text style={styles.inviteSubtitle}>{invite.status}</Text>
                    </View>
                  </View>
                ))
              )}
            </ScrollView>
          </SafeAreaView>
        </Modal>

        <Modal visible={linkVisible} animationType="slide" onRequestClose={() => setLinkVisible(false)}>
          <SafeAreaView style={styles.modalRoot}>
            <ScrollView contentContainerStyle={styles.modalContent}>
              <View style={styles.modalHeader}>
                <Text style={styles.modalTitle}>Device Link</Text>
                <Pressable style={styles.ghostButton} onPress={() => setLinkVisible(false)}>
                  <Text style={styles.ghostButtonText}>Close</Text>
                </Pressable>
              </View>
              <Pressable style={styles.secondaryButton} onPress={handleBeginLink}>
                <Text style={styles.secondaryButtonText}>Generate link code</Text>
              </Pressable>
              <TextInput value={linkCode} editable={false} style={styles.input} />
              <Pressable style={styles.ghostButton} onPress={() => Clipboard.setString(linkCode || '')}>
                <Text style={styles.ghostButtonText}>Copy link code</Text>
              </Pressable>
              <Text style={styles.sectionTitle}>Link another device</Text>
              <TextInput
                value={linkInput}
                onChangeText={setLinkInput}
                placeholder="Enter link code"
                placeholderTextColor={COLORS.muted}
                style={styles.input}
              />
              <Pressable style={styles.primaryButton} onPress={handleLinkDevice}>
                <Text style={styles.primaryButtonText}>Link device</Text>
              </Pressable>
            </ScrollView>
          </SafeAreaView>
        </Modal>

        <Modal visible={localVisible} animationType="slide" onRequestClose={() => setLocalVisible(false)}>
          <SafeAreaView style={styles.modalRoot}>
            <ScrollView contentContainerStyle={styles.modalContent}>
              <View style={styles.modalHeader}>
                <Text style={styles.modalTitle}>Local Info</Text>
                <Pressable style={styles.ghostButton} onPress={() => setLocalVisible(false)}>
                  <Text style={styles.ghostButtonText}>Close</Text>
                </Pressable>
              </View>
              <Pressable style={styles.secondaryButton} onPress={refreshLocalInfo}>
                <Text style={styles.secondaryButtonText}>Refresh bundle and ICE</Text>
              </Pressable>
              <Text style={styles.sectionTitle}>Bundle (hex)</Text>
              <TextInput value={localBundleHex} editable={false} multiline style={styles.inputMulti} />
              <Pressable style={styles.ghostButton} onPress={() => Clipboard.setString(localBundleHex)}>
                <Text style={styles.ghostButtonText}>Copy bundle</Text>
              </Pressable>
              <Text style={styles.sectionTitle}>ICE description</Text>
              <TextInput value={localIce} editable={false} multiline style={styles.inputMulti} />
              <Pressable style={styles.ghostButton} onPress={() => Clipboard.setString(localIce)}>
                <Text style={styles.ghostButtonText}>Copy ICE</Text>
              </Pressable>
            </ScrollView>
          </SafeAreaView>
        </Modal>

        {toast ? (
          <View style={styles.toast}>
            <Text style={styles.toastText}>{toast}</Text>
          </View>
        ) : null}
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: COLORS.bg
  },
  app: {
    flex: 1,
    backgroundColor: COLORS.bg
  },
  appWide: {
    flexDirection: 'row'
  },
  authScreen: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    padding: 24,
    backgroundColor: COLORS.bg
  },
  authCard: {
    width: '100%',
    maxWidth: 420,
    padding: 20,
    backgroundColor: COLORS.panel,
    borderWidth: 1,
    borderColor: COLORS.line,
    gap: 12
  },
  authTitle: {
    fontSize: 22,
    fontFamily: FONT_BASE,
    color: COLORS.ink
  },
  authSubtitle: {
    fontSize: 13,
    fontFamily: FONT_BASE,
    color: COLORS.muted
  },
  authError: {
    fontSize: 12,
    fontFamily: FONT_BASE,
    color: COLORS.danger
  },
  sidebar: {
    width: 360,
    borderRightWidth: 1,
    borderRightColor: COLORS.line,
    backgroundColor: COLORS.panelAlt
  },
  main: {
    flex: 1,
    backgroundColor: COLORS.bg
  },
  sidebarContent: {
    padding: 20,
    gap: 14
  },
  brandRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 16,
    backgroundColor: COLORS.panel,
    borderWidth: 1,
    borderColor: COLORS.line
  },
  brandTitle: {
    fontSize: 20,
    fontWeight: '600',
    fontFamily: FONT_BASE,
    color: COLORS.ink
  },
  brandSubtitle: {
    marginTop: 4,
    fontSize: 12,
    fontFamily: FONT_BASE,
    color: COLORS.muted
  },
  statusDot: {
    width: 12,
    height: 12,
    borderRadius: 6,
    backgroundColor: '#c4c4c4'
  },
  statusDotOn: {
    backgroundColor: COLORS.accentAlt
  },
  statusDotOff: {
    backgroundColor: COLORS.danger
  },
  actionRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 8
  },
  actionButton: {
    flex: 1,
    paddingVertical: 10,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: COLORS.line,
    backgroundColor: COLORS.panel
  },
  actionButtonText: {
    fontSize: 12,
    fontFamily: FONT_BASE,
    textTransform: 'uppercase',
    letterSpacing: 1,
    color: COLORS.muted
  },
  sectionTitle: {
    fontSize: 12,
    fontFamily: FONT_BASE,
    letterSpacing: 2,
    textTransform: 'uppercase',
    color: COLORS.muted
  },
  emptyText: {
    fontSize: 13,
    fontFamily: FONT_BASE,
    color: COLORS.muted
  },
  chatItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 12,
    borderWidth: 1,
    borderColor: COLORS.line,
    backgroundColor: COLORS.panel,
    marginBottom: 8
  },
  chatItemActive: {
    borderColor: COLORS.accent
  },
  chatItemPressed: {
    opacity: 0.8
  },
  chatItemBody: {
    flex: 1,
    paddingRight: 10
  },
  chatTitle: {
    fontSize: 14,
    fontWeight: '600',
    fontFamily: FONT_BASE,
    color: COLORS.ink
  },
  chatSubtitle: {
    marginTop: 4,
    fontSize: 12,
    fontFamily: FONT_BASE,
    color: COLORS.muted
  },
  chatMeta: {
    alignItems: 'flex-end',
    gap: 4
  },
  chatStatus: {
    fontSize: 10,
    textTransform: 'uppercase',
    letterSpacing: 1,
    color: COLORS.muted
  },
  chatStatusActive: {
    color: COLORS.accentAlt
  },
  chatStatusReady: {
    color: COLORS.accent
  },
  unreadPill: {
    marginTop: 4,
    backgroundColor: COLORS.accent,
    borderRadius: 10,
    paddingHorizontal: 6,
    paddingVertical: 2
  },
  unreadText: {
    fontSize: 10,
    color: '#fff',
    fontFamily: FONT_BASE
  },
  input: {
    borderWidth: 1,
    borderColor: COLORS.line,
    backgroundColor: COLORS.panel,
    padding: 10,
    fontSize: 13,
    fontFamily: FONT_BASE,
    color: COLORS.ink
  },
  inputMulti: {
    borderWidth: 1,
    borderColor: COLORS.line,
    backgroundColor: COLORS.panel,
    padding: 10,
    fontSize: 13,
    fontFamily: FONT_BASE,
    color: COLORS.ink,
    minHeight: 90,
    textAlignVertical: 'top'
  },
  row: {
    flexDirection: 'row',
    gap: 8,
    flexWrap: 'wrap'
  },
  rowInput: {
    flex: 1
  },
  primaryButton: {
    paddingVertical: 10,
    paddingHorizontal: 14,
    backgroundColor: COLORS.accent,
    alignItems: 'center'
  },
  primaryButtonText: {
    color: '#fff',
    fontFamily: FONT_BASE,
    fontSize: 12,
    textTransform: 'uppercase',
    letterSpacing: 1
  },
  secondaryButton: {
    paddingVertical: 10,
    paddingHorizontal: 14,
    backgroundColor: COLORS.accentAlt,
    alignItems: 'center'
  },
  secondaryButtonText: {
    color: '#fff',
    fontFamily: FONT_BASE,
    fontSize: 12,
    textTransform: 'uppercase',
    letterSpacing: 1
  },
  ghostButton: {
    paddingVertical: 10,
    paddingHorizontal: 14,
    borderWidth: 1,
    borderColor: COLORS.line,
    alignItems: 'center'
  },
  ghostButtonText: {
    color: COLORS.muted,
    fontFamily: FONT_BASE,
    fontSize: 12,
    textTransform: 'uppercase',
    letterSpacing: 1
  },
  buttonDisabled: {
    opacity: 0.6
  },
  chatPane: {
    flex: 1
  },
  chatHeader: {
    padding: 16,
    borderBottomWidth: 1,
    borderBottomColor: COLORS.line,
    backgroundColor: COLORS.panel,
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12
  },
  chatHeaderTitle: {
    fontSize: 18,
    fontFamily: FONT_BASE,
    color: COLORS.ink
  },
  chatHeaderSubtitle: {
    fontSize: 12,
    fontFamily: FONT_BASE,
    color: COLORS.muted
  },
  headerActions: {
    flexDirection: 'row',
    gap: 8
  },
  backButton: {
    paddingVertical: 6,
    paddingHorizontal: 10,
    borderWidth: 1,
    borderColor: COLORS.line
  },
  backButtonText: {
    fontSize: 12,
    fontFamily: FONT_BASE,
    color: COLORS.muted
  },
  messageList: {
    padding: 16,
    gap: 12
  },
  messageRow: {
    flexDirection: 'row'
  },
  messageRowOut: {
    justifyContent: 'flex-end'
  },
  messageRowIn: {
    justifyContent: 'flex-start'
  },
  messageBubble: {
    maxWidth: '70%',
    padding: 12,
    borderWidth: 1
  },
  messageBubbleOut: {
    backgroundColor: '#fdf4ed',
    borderColor: '#f1c4a5'
  },
  messageBubbleIn: {
    backgroundColor: '#f3ebe2',
    borderColor: '#e5ded6'
  },
  messageText: {
    fontSize: 14,
    fontFamily: FONT_BASE,
    color: COLORS.ink
  },
  messageMeta: {
    marginTop: 6,
    fontSize: 11,
    color: COLORS.muted
  },
  emptyPane: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center'
  },
  composer: {
    flexDirection: 'row',
    gap: 10,
    padding: 12,
    borderTopWidth: 1,
    borderTopColor: COLORS.line,
    backgroundColor: COLORS.panel
  },
  composerInput: {
    flex: 1
  },
  modalRoot: {
    flex: 1,
    backgroundColor: COLORS.bg
  },
  modalContent: {
    padding: 20,
    gap: 16
  },
  modalHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  modalTitle: {
    fontSize: 18,
    fontFamily: FONT_BASE,
    color: COLORS.ink
  },
  field: {
    flex: 1,
    gap: 6
  },
  fieldLabel: {
    fontSize: 12,
    fontFamily: FONT_BASE,
    color: COLORS.muted
  },
  choiceButton: {
    flex: 1,
    paddingVertical: 10,
    alignItems: 'center',
    borderWidth: 1,
    borderColor: COLORS.line,
    backgroundColor: COLORS.panel
  },
  choiceButtonActive: {
    borderColor: COLORS.accent
  },
  choiceButtonText: {
    fontSize: 12,
    fontFamily: FONT_BASE,
    color: COLORS.muted
  },
  choiceButtonTextActive: {
    color: COLORS.accent
  },
  inviteCard: {
    borderWidth: 1,
    borderColor: COLORS.line,
    backgroundColor: COLORS.panel,
    padding: 12,
    gap: 6
  },
  inviteTitle: {
    fontSize: 14,
    fontFamily: FONT_BASE,
    color: COLORS.ink
  },
  inviteSubtitle: {
    fontSize: 11,
    textTransform: 'uppercase',
    letterSpacing: 1,
    color: COLORS.muted
  },
  inviteActions: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 6
  },
  toast: {
    position: 'absolute',
    bottom: 20,
    left: 20,
    right: 20,
    padding: 12,
    backgroundColor: COLORS.panel,
    borderWidth: 1,
    borderColor: COLORS.line
  },
  toastText: {
    fontSize: 12,
    fontFamily: FONT_BASE,
    color: COLORS.ink
  }
});
