// Android TurboModule implementation for Bridge. Spec: app/bridge/BridgeSpec.md.
package com.p2pchat.bridge;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Dynamic;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.module.annotations.ReactModule;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.facebook.react.turbomodule.core.interfaces.TurboModule;

@ReactModule(name = BridgeModule.NAME)
public final class BridgeModule extends ReactContextBaseJavaModule implements TurboModule {
  static final String NAME = "Bridge";
  private static final int CONTENT_TEXT = 1;
  private static final int CONTENT_BINARY = 2;

  private static volatile BridgeModule instance;

  private final ReactApplicationContext reactContext;
  private final long nativeHandle;
  private int listenerCount = 0;

  static {
    System.loadLibrary("p2pchat_bridge");
  }

  public BridgeModule(ReactApplicationContext context) {
    super(context);
    this.reactContext = context;
    this.nativeHandle = nativeCreate();
    instance = this;
  }

  @NonNull
  @Override
  public String getName() {
    return NAME;
  }

  @ReactMethod
  public void start(ReadableMap config) {
    BridgeConfig parsed = BridgeConfig.fromReadableMap(reactContext, config);
    nativeStart(nativeHandle, parsed);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public byte[] localBundle() {
    return nativeLocalBundle(nativeHandle);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String localIce() {
    return nativeLocalIce(nativeHandle);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String beginLink() {
    return nativeBeginLink(nativeHandle);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String localUsername() {
    return nativeLocalUsername(nativeHandle);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public byte[] localIdentityPublicKey() {
    return nativeLocalIdentityPublicKey(nativeHandle);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public byte[] signIdentity(Dynamic message) {
    if (message == null || message.isNull()) {
      throw new IllegalArgumentException("message is required");
    }
    byte[] bytes = BridgePayloads.bytesFromDynamic(message);
    return nativeSignIdentity(nativeHandle, bytes);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String addContact(Dynamic prekeyBundle) {
    if (prekeyBundle == null || prekeyBundle.isNull()) {
      throw new IllegalArgumentException(\"prekeyBundle is required\");
    }
    byte[] bytes = BridgePayloads.bytesFromDynamic(prekeyBundle);
    return nativeAddContact(nativeHandle, bytes);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public String addContactWithUsername(Dynamic prekeyBundle, String username) {
    if (prekeyBundle == null || prekeyBundle.isNull()) {
      throw new IllegalArgumentException(\"prekeyBundle is required\");
    }
    if (username == null) {
      throw new IllegalArgumentException("username is required");
    }
    byte[] bytes = BridgePayloads.bytesFromDynamic(prekeyBundle);
    return nativeAddContactWithUsername(nativeHandle, bytes, username);
  }

  @ReactMethod
  public void send(String chatId, Dynamic payload) {
    if (payload == null || payload.isNull()) {
      throw new IllegalArgumentException("payload is required");
    }
    ReadableType type = payload.getType();
    if (type == ReadableType.String) {
      byte[] bytes = payload.asString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
      nativeSend(nativeHandle, chatId, bytes, CONTENT_TEXT);
      return;
    }
    byte[] bytes = BridgePayloads.bytesFromDynamic(payload);
    nativeSend(nativeHandle, chatId, bytes, CONTENT_BINARY);
  }

  @ReactMethod(isBlockingSynchronousMethod = true)
  public WritableArray getHistory(String chatId, double cursor, double limit) {
    String json = nativeGetHistoryJson(nativeHandle, chatId, (long) cursor, (int) limit);
    return BridgePayloads.historyArrayFromJson(json);
  }

  @ReactMethod
  public void linkDevice(String linkCode) {
    nativeLinkDevice(nativeHandle, linkCode);
  }

  @ReactMethod
  public void updateProfile(String username, String password) {
    nativeUpdateProfile(nativeHandle, username, password);
  }

  @ReactMethod
  public void connectPeer(ReadableMap peerInfo) {
    if (peerInfo == null) {
      throw new IllegalArgumentException("peerInfo is required");
    }
    String peerId = peerInfo.hasKey("peerId") ? peerInfo.getString("peerId") : null;
    String address = peerInfo.hasKey("address") ? peerInfo.getString("address") : null;
    int port = peerInfo.hasKey("port") ? peerInfo.getInt("port") : 0;
    String iceBlob = peerInfo.hasKey("iceBlob") ? peerInfo.getString("iceBlob") : null;
    if (peerId == null || peerId.isEmpty()) {
      throw new IllegalArgumentException("peerId is required");
    }
    nativeConnectPeer(nativeHandle, peerId, address, port, iceBlob);
  }

  @ReactMethod
  public void addListener(String eventName) {
    listenerCount += 1;
  }

  @ReactMethod
  public void removeListeners(double count) {
    int remove = (int) count;
    listenerCount = Math.max(0, listenerCount - remove);
  }

  @Override
  public void invalidate() {
    nativeDestroy(nativeHandle);
    if (instance == this) {
      instance = null;
    }
  }

  private void emit(String eventName, String payloadJson) {
    if (listenerCount <= 0) {
      return;
    }
    Object payload = BridgePayloads.payloadFromJson(payloadJson);
    reactContext
        .getJSModule(DeviceEventManagerModule.RCTDeviceEventEmitter.class)
        .emit(eventName, payload);
  }

  public static void emitEvent(String eventName, String payloadJson) {
    BridgeModule current = instance;
    if (current != null) {
      current.emit(eventName, payloadJson);
    }
  }

  private static native long nativeCreate();
  private static native void nativeDestroy(long handle);
  private static native void nativeStart(long handle, BridgeConfig config);
  private static native byte[] nativeLocalBundle(long handle);
  private static native String nativeLocalIce(long handle);
  private static native String nativeBeginLink(long handle);
  private static native String nativeAddContact(long handle, byte[] prekeyBundle);
  private static native String nativeAddContactWithUsername(long handle, byte[] prekeyBundle, String username);
  private static native String nativeLocalUsername(long handle);
  private static native byte[] nativeLocalIdentityPublicKey(long handle);
  private static native byte[] nativeSignIdentity(long handle, byte[] message);
  private static native void nativeConnectPeer(long handle, String peerId, String address, int port, String iceBlob);
  private static native void nativeSend(long handle, String chatId, byte[] payload, int contentType);
  private static native String nativeGetHistoryJson(long handle, String chatId, long cursor, int limit);
  private static native void nativeLinkDevice(long handle, String linkCode);
  private static native void nativeUpdateProfile(long handle, String username, String password);
}
