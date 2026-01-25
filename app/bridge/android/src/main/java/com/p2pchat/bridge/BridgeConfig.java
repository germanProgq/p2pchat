// Android bridge config parsing. Spec: app/bridge/BridgeSpec.md.
package com.p2pchat.bridge;

import android.content.Context;

import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;

import java.util.ArrayList;
import java.util.List;

final class BridgeConfig {
  static final int ICE_TYPE_HOST = 1;
  static final int ICE_TYPE_SRFLX = 2;
  static final int ICE_TYPE_RELAY = 3;

  final String identityPath;
  final String storagePath;
  final String schemaPath;
  final String username;
  final String password;
  final byte[] masterKey;
  final String transportKind;
  final TransportConfig transport;
  final QuicConfig quic;
  final WebRtcConfig webrtc;
  final int oneTimePrekeys;
  final int signedPrekeyId;
  final int oneTimeStartId;
  final long handshakeBaseDelayMs;
  final long handshakeMaxDelayMs;
  final int handshakeMaxAttempts;

  private BridgeConfig(String identityPath,
                       String storagePath,
                       String schemaPath,
                       String username,
                       String password,
                       byte[] masterKey,
                       String transportKind,
                       TransportConfig transport,
                       QuicConfig quic,
                       WebRtcConfig webrtc,
                       int oneTimePrekeys,
                       int signedPrekeyId,
                       int oneTimeStartId,
                       long handshakeBaseDelayMs,
                       long handshakeMaxDelayMs,
                       int handshakeMaxAttempts) {
    this.identityPath = identityPath;
    this.storagePath = storagePath;
    this.schemaPath = schemaPath;
    this.username = username;
    this.password = password;
    this.masterKey = masterKey;
    this.transportKind = transportKind;
    this.transport = transport;
    this.quic = quic;
    this.webrtc = webrtc;
    this.oneTimePrekeys = oneTimePrekeys;
    this.signedPrekeyId = signedPrekeyId;
    this.oneTimeStartId = oneTimeStartId;
    this.handshakeBaseDelayMs = handshakeBaseDelayMs;
    this.handshakeMaxDelayMs = handshakeMaxDelayMs;
    this.handshakeMaxAttempts = handshakeMaxAttempts;
  }

  static BridgeConfig fromReadableMap(Context context, ReadableMap map) {
    String identityPath = requireString(map, "identityPath");
    String storagePath = requireString(map, "storagePath");
    String schemaPath = requireString(map, "schemaPath");
    String username = optString(map, "username", "");
    String password = optString(map, "password", "");

    byte[] masterKey = null;
    if (map.hasKey("masterKey") && !map.isNull("masterKey")) {
      com.facebook.react.bridge.Dynamic dynamic = map.getDynamic("masterKey");
      if (dynamic.getType() == ReadableType.String) {
        masterKey = BridgePayloads.bytesFromObject(dynamic.asString());
      } else if (dynamic.getType() == ReadableType.Array) {
        masterKey = BridgePayloads.bytesFromReadableArray(dynamic.asArray());
      } else if (dynamic.getType() == ReadableType.Map) {
        masterKey = BridgePayloads.bytesFromObject(dynamic.asMap());
      }
    }
    if (masterKey == null) {
      masterKey = BridgeKeyStore.loadOrCreate(context);
    }

    String transportKind = optString(map, "transportKind", "quic");

    TransportConfig transport = TransportConfig.fromReadableMap(optMap(map, "transport"));
    QuicConfig quic = QuicConfig.fromReadableMap(optMap(map, "quic"));
    WebRtcConfig webrtc = WebRtcConfig.fromReadableMap(optMap(map, "webrtc"));

    int oneTimePrekeys = optInt(map, "oneTimePrekeys", 50);
    int signedPrekeyId = optInt(map, "signedPrekeyId", 1);
    int oneTimeStartId = optInt(map, "oneTimeStartId", 1000);
    long handshakeBaseDelayMs = optLong(map, "handshakeBaseDelayMs", 200);
    long handshakeMaxDelayMs = optLong(map, "handshakeMaxDelayMs", 2000);
    int handshakeMaxAttempts = optInt(map, "handshakeMaxAttempts", 5);

    return new BridgeConfig(identityPath,
        storagePath,
        schemaPath,
        username,
        password,
        masterKey,
        transportKind,
        transport,
        quic,
        webrtc,
        oneTimePrekeys,
        signedPrekeyId,
        oneTimeStartId,
        handshakeBaseDelayMs,
        handshakeMaxDelayMs,
        handshakeMaxAttempts);
  }

  private static String requireString(ReadableMap map, String key) {
    if (!map.hasKey(key) || map.isNull(key)) {
      throw new IllegalArgumentException("Missing required field: " + key);
    }
    String value = map.getString(key);
    if (value == null || value.isEmpty()) {
      throw new IllegalArgumentException("Empty required field: " + key);
    }
    return value;
  }

  private static String optString(ReadableMap map, String key, String fallback) {
    if (!map.hasKey(key) || map.isNull(key)) {
      return fallback;
    }
    String value = map.getString(key);
    return value == null ? fallback : value;
  }

  private static int optInt(ReadableMap map, String key, int fallback) {
    if (!map.hasKey(key) || map.isNull(key)) {
      return fallback;
    }
    return (int) map.getDouble(key);
  }

  private static long optLong(ReadableMap map, String key, long fallback) {
    if (!map.hasKey(key) || map.isNull(key)) {
      return fallback;
    }
    return (long) map.getDouble(key);
  }

  private static double optDouble(ReadableMap map, String key, double fallback) {
    if (!map.hasKey(key) || map.isNull(key)) {
      return fallback;
    }
    return map.getDouble(key);
  }

  private static ReadableMap optMap(ReadableMap map, String key) {
    if (!map.hasKey(key) || map.isNull(key)) {
      return null;
    }
    return map.getMap(key);
  }

  private static ReadableArray optArray(ReadableMap map, String key) {
    if (!map.hasKey(key) || map.isNull(key)) {
      return null;
    }
    return map.getArray(key);
  }

  static final class TransportConfig {
    final int maxInFlight;
    final int maxQueueBytes;
    final RetryPolicy retry;

    private TransportConfig(int maxInFlight, int maxQueueBytes, RetryPolicy retry) {
      this.maxInFlight = maxInFlight;
      this.maxQueueBytes = maxQueueBytes;
      this.retry = retry;
    }

    static TransportConfig fromReadableMap(ReadableMap map) {
      if (map == null) {
        return new TransportConfig(32, 1 << 20, RetryPolicy.defaults());
      }
      int maxInFlight = optInt(map, "maxInFlight", 32);
      int maxQueueBytes = optInt(map, "maxQueueBytes", 1 << 20);
      RetryPolicy retry = RetryPolicy.fromReadableMap(optMap(map, "retry"));
      return new TransportConfig(maxInFlight, maxQueueBytes, retry);
    }
  }

  static final class RetryPolicy {
    final long baseDelayMs;
    final long maxDelayMs;
    final int maxAttempts;
    final double jitterRatio;

    private RetryPolicy(long baseDelayMs, long maxDelayMs, int maxAttempts, double jitterRatio) {
      this.baseDelayMs = baseDelayMs;
      this.maxDelayMs = maxDelayMs;
      this.maxAttempts = maxAttempts;
      this.jitterRatio = jitterRatio;
    }

    static RetryPolicy defaults() {
      return new RetryPolicy(100, 2000, 5, 0.2);
    }

    static RetryPolicy fromReadableMap(ReadableMap map) {
      if (map == null) {
        return defaults();
      }
      long baseDelayMs = optLong(map, "baseDelayMs", 100);
      long maxDelayMs = optLong(map, "maxDelayMs", 2000);
      int maxAttempts = optInt(map, "maxAttempts", 5);
      double jitterRatio = optDouble(map, "jitterRatio", 0.2);
      return new RetryPolicy(baseDelayMs, maxDelayMs, maxAttempts, jitterRatio);
    }
  }

  static final class QuicConfig {
    final String bindAddress;
    final int bindPort;
    final int maxDatagramSize;
    final IceConfig ice;

    private QuicConfig(String bindAddress, int bindPort, int maxDatagramSize, IceConfig ice) {
      this.bindAddress = bindAddress;
      this.bindPort = bindPort;
      this.maxDatagramSize = maxDatagramSize;
      this.ice = ice;
    }

    static QuicConfig fromReadableMap(ReadableMap map) {
      if (map == null) {
        return new QuicConfig("0.0.0.0", 0, 1200, IceConfig.defaults());
      }
      String bindAddress = optString(map, "bindAddress", "0.0.0.0");
      int bindPort = optInt(map, "bindPort", 0);
      int maxDatagramSize = optInt(map, "maxDatagramSize", 1200);
      IceConfig ice = IceConfig.fromReadableMap(optMap(map, "ice"));
      return new QuicConfig(bindAddress, bindPort, maxDatagramSize, ice);
    }
  }

  static final class WebRtcConfig {
    final String bindAddress;
    final int bindPort;
    final int maxDatagramSize;
    final IceConfig ice;

    private WebRtcConfig(String bindAddress, int bindPort, int maxDatagramSize, IceConfig ice) {
      this.bindAddress = bindAddress;
      this.bindPort = bindPort;
      this.maxDatagramSize = maxDatagramSize;
      this.ice = ice;
    }

    static WebRtcConfig fromReadableMap(ReadableMap map) {
      if (map == null) {
        return new WebRtcConfig("0.0.0.0", 0, 1200, IceConfig.defaults());
      }
      String bindAddress = optString(map, "bindAddress", "0.0.0.0");
      int bindPort = optInt(map, "bindPort", 0);
      int maxDatagramSize = optInt(map, "maxDatagramSize", 1200);
      IceConfig ice = IceConfig.fromReadableMap(optMap(map, "ice"));
      return new WebRtcConfig(bindAddress, bindPort, maxDatagramSize, ice);
    }
  }

  static final class IceConfig {
    final List<String> stunServers;
    final String bindAddress;
    final int bindPort;
    final int timeoutMs;
    final List<RelayCandidate> relayCandidates;

    private IceConfig(List<String> stunServers,
                      String bindAddress,
                      int bindPort,
                      int timeoutMs,
                      List<RelayCandidate> relayCandidates) {
      this.stunServers = stunServers;
      this.bindAddress = bindAddress;
      this.bindPort = bindPort;
      this.timeoutMs = timeoutMs;
      this.relayCandidates = relayCandidates;
    }

    static IceConfig defaults() {
      return new IceConfig(new ArrayList<>(), "0.0.0.0", 0, 1500, new ArrayList<>());
    }

    static IceConfig fromReadableMap(ReadableMap map) {
      if (map == null) {
        return defaults();
      }
      List<String> stunServers = new ArrayList<>();
      ReadableArray stunArray = optArray(map, "stunServers");
      if (stunArray != null) {
        for (int i = 0; i < stunArray.size(); i++) {
          if (!stunArray.isNull(i)) {
            stunServers.add(stunArray.getString(i));
          }
        }
      }
      String bindAddress = optString(map, "bindAddress", "0.0.0.0");
      int bindPort = optInt(map, "bindPort", 0);
      int timeoutMs = optInt(map, "timeoutMs", 1500);
      List<RelayCandidate> relayCandidates = new ArrayList<>();
      ReadableArray relayArray = optArray(map, "relayCandidates");
      if (relayArray != null) {
        for (int i = 0; i < relayArray.size(); i++) {
          if (relayArray.isNull(i)) {
            continue;
          }
          ReadableMap entry = relayArray.getMap(i);
          relayCandidates.add(RelayCandidate.fromReadableMap(entry));
        }
      }
      return new IceConfig(stunServers, bindAddress, bindPort, timeoutMs, relayCandidates);
    }
  }

  static final class RelayCandidate {
    final int type;
    final String address;
    final int port;
    final int priority;

    private RelayCandidate(int type, String address, int port, int priority) {
      this.type = type;
      this.address = address;
      this.port = port;
      this.priority = priority;
    }

    static RelayCandidate fromReadableMap(ReadableMap map) {
      if (map == null) {
        throw new IllegalArgumentException("relayCandidates entry missing");
      }
      int type = parseType(map.getDynamic("type"));
      String address = map.hasKey("address") ? map.getString("address") : "";
      int port = map.hasKey("port") ? (int) map.getDouble("port") : 0;
      int priority = map.hasKey("priority") ? (int) map.getDouble("priority") : 0;
      if (address == null || address.isEmpty()) {
        throw new IllegalArgumentException("relayCandidates.address missing");
      }
      return new RelayCandidate(type, address, port, priority);
    }

    private static int parseType(com.facebook.react.bridge.Dynamic value) {
      if (value == null || value.isNull()) {
        return ICE_TYPE_RELAY;
      }
      ReadableType type = value.getType();
      if (type == ReadableType.Number) {
        int numeric = (int) value.asDouble();
        if (numeric == ICE_TYPE_HOST || numeric == ICE_TYPE_SRFLX || numeric == ICE_TYPE_RELAY) {
          return numeric;
        }
      } else if (type == ReadableType.String) {
        String text = value.asString();
        if (text != null) {
          switch (text.toLowerCase()) {
            case "host":
              return ICE_TYPE_HOST;
            case "srflx":
              return ICE_TYPE_SRFLX;
            case "relay":
              return ICE_TYPE_RELAY;
            default:
              break;
          }
        }
      }
      return ICE_TYPE_RELAY;
    }
  }
}
