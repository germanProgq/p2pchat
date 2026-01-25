// JNI bridge for exposing core bridge to Android TurboModule. Spec: app/bridge/BridgeSpec.md.
#include <jni.h>

#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "bridge/Bridge.h"
#include "bridge/BridgeJson.h"
#include "transport/Ice.h"

namespace {

JavaVM* g_vm = nullptr;
jclass g_bridge_class = nullptr;
jmethodID g_emit_method = nullptr;
std::mutex g_emit_mutex;

class ScopedJniEnv {
 public:
  ScopedJniEnv() {
    if (!g_vm) {
      return;
    }
    JNIEnv* env = nullptr;
    if (g_vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
      env_ = env;
      attached_ = false;
      return;
    }
    if (g_vm->AttachCurrentThread(&env_, nullptr) == JNI_OK) {
      attached_ = true;
    }
  }

  ~ScopedJniEnv() {
    if (attached_ && g_vm) {
      g_vm->DetachCurrentThread();
    }
  }

  JNIEnv* env() const { return env_; }

 private:
  JNIEnv* env_ = nullptr;
  bool attached_ = false;
};

void emitEvent(const std::string& name, const std::string& payload) {
  std::lock_guard<std::mutex> lock(g_emit_mutex);
  if (!g_vm || !g_bridge_class || !g_emit_method) {
    return;
  }
  ScopedJniEnv scoped;
  JNIEnv* env = scoped.env();
  if (!env) {
    return;
  }
  jstring jname = env->NewStringUTF(name.c_str());
  jstring jpayload = env->NewStringUTF(payload.c_str());
  env->CallStaticVoidMethod(g_bridge_class, g_emit_method, jname, jpayload);
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
  }
  env->DeleteLocalRef(jname);
  env->DeleteLocalRef(jpayload);
}

std::string toString(JNIEnv* env, jstring value) {
  if (!value) {
    return {};
  }
  const char* chars = env->GetStringUTFChars(value, nullptr);
  std::string out = chars ? chars : "";
  env->ReleaseStringUTFChars(value, chars);
  return out;
}

std::vector<uint8_t> toBytes(JNIEnv* env, jbyteArray array) {
  std::vector<uint8_t> out;
  if (!array) {
    return out;
  }
  jsize len = env->GetArrayLength(array);
  out.resize(static_cast<size_t>(len));
  env->GetByteArrayRegion(array, 0, len, reinterpret_cast<jbyte*>(out.data()));
  return out;
}

jobject getFieldObject(JNIEnv* env, jobject obj, const char* name, const char* sig) {
  jclass cls = env->GetObjectClass(obj);
  jfieldID field = env->GetFieldID(cls, name, sig);
  env->DeleteLocalRef(cls);
  if (!field) {
    return nullptr;
  }
  return env->GetObjectField(obj, field);
}

jint getFieldInt(JNIEnv* env, jobject obj, const char* name) {
  jclass cls = env->GetObjectClass(obj);
  jfieldID field = env->GetFieldID(cls, name, "I");
  env->DeleteLocalRef(cls);
  if (!field) {
    return 0;
  }
  return env->GetIntField(obj, field);
}

jlong getFieldLong(JNIEnv* env, jobject obj, const char* name) {
  jclass cls = env->GetObjectClass(obj);
  jfieldID field = env->GetFieldID(cls, name, "J");
  env->DeleteLocalRef(cls);
  if (!field) {
    return 0;
  }
  return env->GetLongField(obj, field);
}

jdouble getFieldDouble(JNIEnv* env, jobject obj, const char* name) {
  jclass cls = env->GetObjectClass(obj);
  jfieldID field = env->GetFieldID(cls, name, "D");
  env->DeleteLocalRef(cls);
  if (!field) {
    return 0.0;
  }
  return env->GetDoubleField(obj, field);
}

std::vector<std::string> readStringList(JNIEnv* env, jobject list) {
  std::vector<std::string> out;
  if (!list) {
    return out;
  }
  jclass list_cls = env->GetObjectClass(list);
  jmethodID size_method = env->GetMethodID(list_cls, "size", "()I");
  jmethodID get_method = env->GetMethodID(list_cls, "get", "(I)Ljava/lang/Object;");
  jint size = env->CallIntMethod(list, size_method);
  out.reserve(static_cast<size_t>(size));
  for (jint i = 0; i < size; ++i) {
    jobject item = env->CallObjectMethod(list, get_method, i);
    if (item) {
      jstring text = static_cast<jstring>(item);
      out.push_back(toString(env, text));
      env->DeleteLocalRef(item);
    }
  }
  env->DeleteLocalRef(list_cls);
  return out;
}

transport::IceConfig parseIceConfig(JNIEnv* env, jobject ice_obj) {
  transport::IceConfig config;
  if (!ice_obj) {
    return config;
  }
  jobject stun_list = getFieldObject(env, ice_obj, "stunServers", "Ljava/util/List;");
  config.stun_servers = readStringList(env, stun_list);
  if (stun_list) {
    env->DeleteLocalRef(stun_list);
  }
  jstring bind_addr = static_cast<jstring>(getFieldObject(env, ice_obj, "bindAddress", "Ljava/lang/String;"));
  config.bind_address = toString(env, bind_addr);
  if (bind_addr) {
    env->DeleteLocalRef(bind_addr);
  }
  config.bind_port = static_cast<uint16_t>(getFieldInt(env, ice_obj, "bindPort"));
  config.timeout_ms = static_cast<int>(getFieldInt(env, ice_obj, "timeoutMs"));

  jobject relay_list = getFieldObject(env, ice_obj, "relayCandidates", "Ljava/util/List;");
  if (relay_list) {
    jclass list_cls = env->GetObjectClass(relay_list);
    jmethodID size_method = env->GetMethodID(list_cls, "size", "()I");
    jmethodID get_method = env->GetMethodID(list_cls, "get", "(I)Ljava/lang/Object;");
    jint size = env->CallIntMethod(relay_list, size_method);
    config.relay_candidates.reserve(static_cast<size_t>(size));
    for (jint i = 0; i < size; ++i) {
      jobject candidate = env->CallObjectMethod(relay_list, get_method, i);
      if (!candidate) {
        continue;
      }
      int type = getFieldInt(env, candidate, "type");
      jstring address = static_cast<jstring>(getFieldObject(env, candidate, "address", "Ljava/lang/String;"));
      transport::IceCandidate entry;
      entry.type = static_cast<transport::IceCandidateType>(type);
      entry.address = toString(env, address);
      entry.port = static_cast<uint16_t>(getFieldInt(env, candidate, "port"));
      entry.priority = static_cast<uint32_t>(getFieldInt(env, candidate, "priority"));
      config.relay_candidates.push_back(entry);
      if (address) {
        env->DeleteLocalRef(address);
      }
      env->DeleteLocalRef(candidate);
    }
    env->DeleteLocalRef(list_cls);
    env->DeleteLocalRef(relay_list);
  }
  return config;
}

transport::TransportConfig parseTransportConfig(JNIEnv* env, jobject transport_obj) {
  transport::TransportConfig config;
  if (!transport_obj) {
    return config;
  }
  config.max_in_flight = static_cast<size_t>(getFieldInt(env, transport_obj, "maxInFlight"));
  config.max_queue_bytes = static_cast<size_t>(getFieldInt(env, transport_obj, "maxQueueBytes"));
  jobject retry_obj = getFieldObject(env, transport_obj, "retry", "Lcom/p2pchat/bridge/BridgeConfig$RetryPolicy;");
  if (retry_obj) {
    config.retry.base_delay_ms = getFieldLong(env, retry_obj, "baseDelayMs");
    config.retry.max_delay_ms = getFieldLong(env, retry_obj, "maxDelayMs");
    config.retry.max_attempts = static_cast<uint32_t>(getFieldInt(env, retry_obj, "maxAttempts"));
    config.retry.jitter_ratio = getFieldDouble(env, retry_obj, "jitterRatio");
    env->DeleteLocalRef(retry_obj);
  }
  return config;
}

transport::QuicConfig parseQuicConfig(JNIEnv* env, jobject quic_obj) {
  transport::QuicConfig config;
  if (!quic_obj) {
    return config;
  }
  jstring bind_addr = static_cast<jstring>(getFieldObject(env, quic_obj, "bindAddress", "Ljava/lang/String;"));
  config.bind_address = toString(env, bind_addr);
  if (bind_addr) {
    env->DeleteLocalRef(bind_addr);
  }
  config.bind_port = static_cast<uint16_t>(getFieldInt(env, quic_obj, "bindPort"));
  config.max_datagram_size = static_cast<size_t>(getFieldInt(env, quic_obj, "maxDatagramSize"));
  jobject ice_obj = getFieldObject(env, quic_obj, "ice", "Lcom/p2pchat/bridge/BridgeConfig$IceConfig;");
  config.ice = parseIceConfig(env, ice_obj);
  if (ice_obj) {
    env->DeleteLocalRef(ice_obj);
  }
  return config;
}

transport::WebRtcConfig parseWebRtcConfig(JNIEnv* env, jobject webrtc_obj) {
  transport::WebRtcConfig config;
  if (!webrtc_obj) {
    return config;
  }
  jstring bind_addr = static_cast<jstring>(getFieldObject(env, webrtc_obj, "bindAddress", "Ljava/lang/String;"));
  config.bind_address = toString(env, bind_addr);
  if (bind_addr) {
    env->DeleteLocalRef(bind_addr);
  }
  config.bind_port = static_cast<uint16_t>(getFieldInt(env, webrtc_obj, "bindPort"));
  config.max_datagram_size = static_cast<size_t>(getFieldInt(env, webrtc_obj, "maxDatagramSize"));
  jobject ice_obj = getFieldObject(env, webrtc_obj, "ice", "Lcom/p2pchat/bridge/BridgeConfig$IceConfig;");
  config.ice = parseIceConfig(env, ice_obj);
  if (ice_obj) {
    env->DeleteLocalRef(ice_obj);
  }
  return config;
}

bridge::NodeConfig parseBridgeConfig(JNIEnv* env, jobject config_obj) {
  bridge::NodeConfig config;
  if (!config_obj) {
    return config;
  }
  jstring identity_path = static_cast<jstring>(getFieldObject(env, config_obj, "identityPath", "Ljava/lang/String;"));
  jstring storage_path = static_cast<jstring>(getFieldObject(env, config_obj, "storagePath", "Ljava/lang/String;"));
  jstring schema_path = static_cast<jstring>(getFieldObject(env, config_obj, "schemaPath", "Ljava/lang/String;"));
  jstring username = static_cast<jstring>(getFieldObject(env, config_obj, "username", "Ljava/lang/String;"));
  jstring password = static_cast<jstring>(getFieldObject(env, config_obj, "password", "Ljava/lang/String;"));
  jstring transport_kind = static_cast<jstring>(getFieldObject(env, config_obj, "transportKind", "Ljava/lang/String;"));
  jbyteArray master_key = static_cast<jbyteArray>(getFieldObject(env, config_obj, "masterKey", "[B"));

  config.identity_path = toString(env, identity_path);
  config.storage_path = toString(env, storage_path);
  config.schema_path = toString(env, schema_path);
  config.username = toString(env, username);
  config.password = toString(env, password);
  config.master_key = toBytes(env, master_key);

  std::string kind = toString(env, transport_kind);
  if (kind == "webrtc") {
    config.transport_kind = bridge::TransportKind::WebRtc;
  } else if (kind == "loopback") {
    config.transport_kind = bridge::TransportKind::Loopback;
  } else {
    config.transport_kind = bridge::TransportKind::Quic;
  }

  jobject transport_obj = getFieldObject(env, config_obj, "transport", "Lcom/p2pchat/bridge/BridgeConfig$TransportConfig;");
  jobject quic_obj = getFieldObject(env, config_obj, "quic", "Lcom/p2pchat/bridge/BridgeConfig$QuicConfig;");
  jobject webrtc_obj = getFieldObject(env, config_obj, "webrtc", "Lcom/p2pchat/bridge/BridgeConfig$WebRtcConfig;");

  config.transport = parseTransportConfig(env, transport_obj);
  config.quic = parseQuicConfig(env, quic_obj);
  config.webrtc = parseWebRtcConfig(env, webrtc_obj);

  config.one_time_prekeys = static_cast<size_t>(getFieldInt(env, config_obj, "oneTimePrekeys"));
  config.signed_prekey_id = static_cast<uint32_t>(getFieldInt(env, config_obj, "signedPrekeyId"));
  config.one_time_start_id = static_cast<uint32_t>(getFieldInt(env, config_obj, "oneTimeStartId"));
  config.handshake_base_delay_ms = static_cast<int64_t>(getFieldLong(env, config_obj, "handshakeBaseDelayMs"));
  config.handshake_max_delay_ms = static_cast<int64_t>(getFieldLong(env, config_obj, "handshakeMaxDelayMs"));
  config.handshake_max_attempts = static_cast<uint32_t>(getFieldInt(env, config_obj, "handshakeMaxAttempts"));

  if (identity_path) {
    env->DeleteLocalRef(identity_path);
  }
  if (storage_path) {
    env->DeleteLocalRef(storage_path);
  }
  if (schema_path) {
    env->DeleteLocalRef(schema_path);
  }
  if (username) {
    env->DeleteLocalRef(username);
  }
  if (password) {
    env->DeleteLocalRef(password);
  }
  if (transport_kind) {
    env->DeleteLocalRef(transport_kind);
  }
  if (master_key) {
    env->DeleteLocalRef(master_key);
  }
  if (transport_obj) {
    env->DeleteLocalRef(transport_obj);
  }
  if (quic_obj) {
    env->DeleteLocalRef(quic_obj);
  }
  if (webrtc_obj) {
    env->DeleteLocalRef(webrtc_obj);
  }
  return config;
}

std::string historyToJson(const std::vector<bridge::HistoryMessage>& history) {
  std::string out;
  out.reserve(128 * history.size() + 2);
  out.push_back('[');
  for (size_t i = 0; i < history.size(); ++i) {
    if (i > 0) {
      out.push_back(',');
    }
    out += bridge::toJsonPayload(history[i]);
  }
  out.push_back(']');
  return out;
}

class BridgeInstance {
 public:
  BridgeInstance() : backend(std::make_shared<bridge::CoreAdapter>()), bridge(std::make_unique<bridge::Bridge>(backend)) {
    bridge->onMessage = [](const bridge::IncomingMessage& message) {
      emitEvent("onMessage", bridge::toJsonPayload(message));
    };
    bridge->onConnectionChange = [](const bridge::ConnectionEvent& event) {
      emitEvent("onConnectionChange", bridge::toJsonPayload(event));
    };
    bridge->onPeerStatus = [](const bridge::PeerStatusEvent& event) {
      emitEvent("onPeerStatus", bridge::toJsonPayload(event));
    };
    bridge->onError = [](const bridge::ErrorEvent& event) {
      emitEvent("onError", bridge::toJsonPayload(event));
    };
  }

  std::shared_ptr<bridge::CoreAdapter> backend;
  std::unique_ptr<bridge::Bridge> bridge;
};

BridgeInstance* fromHandle(jlong handle) {
  return reinterpret_cast<BridgeInstance*>(handle);
}

}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void*) {
  g_vm = vm;
  JNIEnv* env = nullptr;
  if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || !env) {
    return JNI_ERR;
  }
  jclass local = env->FindClass("com/p2pchat/bridge/BridgeModule");
  if (!local) {
    return JNI_ERR;
  }
  g_bridge_class = reinterpret_cast<jclass>(env->NewGlobalRef(local));
  env->DeleteLocalRef(local);
  g_emit_method = env->GetStaticMethodID(g_bridge_class, "emitEvent", "(Ljava/lang/String;Ljava/lang/String;)V");
  if (!g_emit_method) {
    return JNI_ERR;
  }
  return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT void JNICALL JNI_OnUnload(JavaVM*, void*) {
  if (!g_vm) {
    return;
  }
  ScopedJniEnv scoped;
  JNIEnv* env = scoped.env();
  if (env && g_bridge_class) {
    env->DeleteGlobalRef(g_bridge_class);
  }
  g_bridge_class = nullptr;
  g_emit_method = nullptr;
  g_vm = nullptr;
}

extern "C" JNIEXPORT jlong JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeCreate(JNIEnv*, jclass) {
  auto instance = std::make_unique<BridgeInstance>();
  return reinterpret_cast<jlong>(instance.release());
}

extern "C" JNIEXPORT void JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeDestroy(JNIEnv*, jclass, jlong handle) {
  auto* instance = fromHandle(handle);
  delete instance;
}

extern "C" JNIEXPORT void JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeStart(JNIEnv* env,
                                                                                  jclass,
                                                                                  jlong handle,
                                                                                  jobject config_obj) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return;
  }
  bridge::NodeConfig config = parseBridgeConfig(env, config_obj);
  instance->bridge->start(config);
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeLocalBundle(JNIEnv* env,
                                                                                             jclass,
                                                                                             jlong handle) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return env->NewByteArray(0);
  }
  std::vector<uint8_t> bundle = instance->bridge->localBundle();
  jbyteArray out = env->NewByteArray(static_cast<jsize>(bundle.size()));
  if (!out) {
    return env->NewByteArray(0);
  }
  if (!bundle.empty()) {
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(bundle.size()),
                            reinterpret_cast<const jbyte*>(bundle.data()));
  }
  return out;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeLocalIce(JNIEnv* env,
                                                                                       jclass,
                                                                                       jlong handle) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return env->NewStringUTF("");
  }
  std::string ice = instance->bridge->localIce();
  return env->NewStringUTF(ice.c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeBeginLink(JNIEnv* env,
                                                                                         jclass,
                                                                                         jlong handle) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return env->NewStringUTF("");
  }
  std::string code = instance->bridge->beginLink();
  return env->NewStringUTF(code.c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeLocalUsername(JNIEnv* env,
                                                                                             jclass,
                                                                                             jlong handle) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return env->NewStringUTF("");
  }
  std::string name = instance->bridge->localUsername();
  return env->NewStringUTF(name.c_str());
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeLocalIdentityPublicKey(JNIEnv* env,
                                                                                                         jclass,
                                                                                                         jlong handle) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return env->NewByteArray(0);
  }
  std::vector<uint8_t> key = instance->bridge->localIdentityPublicKey();
  jbyteArray out = env->NewByteArray(static_cast<jsize>(key.size()));
  if (!out) {
    return env->NewByteArray(0);
  }
  if (!key.empty()) {
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(key.size()),
                            reinterpret_cast<const jbyte*>(key.data()));
  }
  return out;
}

extern "C" JNIEXPORT jbyteArray JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeSignIdentity(JNIEnv* env,
                                                                                                jclass,
                                                                                                jlong handle,
                                                                                                jbyteArray message) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return env->NewByteArray(0);
  }
  std::vector<uint8_t> bytes = toBytes(env, message);
  std::vector<uint8_t> sig = instance->bridge->signIdentity(bytes);
  jbyteArray out = env->NewByteArray(static_cast<jsize>(sig.size()));
  if (!out) {
    return env->NewByteArray(0);
  }
  if (!sig.empty()) {
    env->SetByteArrayRegion(out, 0, static_cast<jsize>(sig.size()),
                            reinterpret_cast<const jbyte*>(sig.data()));
  }
  return out;
}

extern "C" JNIEXPORT jstring JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeAddContact(JNIEnv* env,
                                                                                          jclass,
                                                                                          jlong handle,
                                                                                          jbyteArray bundle) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return env->NewStringUTF("");
  }
  std::vector<uint8_t> bytes = toBytes(env, bundle);
  std::string peer_id = instance->bridge->addContact(bytes);
  return env->NewStringUTF(peer_id.c_str());
}

extern "C" JNIEXPORT jstring JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeAddContactWithUsername(JNIEnv* env,
                                                                                                      jclass,
                                                                                                      jlong handle,
                                                                                                      jbyteArray bundle,
                                                                                                      jstring username) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return env->NewStringUTF("");
  }
  std::vector<uint8_t> bytes = toBytes(env, bundle);
  std::string name = toString(env, username);
  std::string peer_id = instance->bridge->addContactWithUsername(bytes, name);
  return env->NewStringUTF(peer_id.c_str());
}

extern "C" JNIEXPORT void JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeSend(JNIEnv* env,
                                                                                jclass,
                                                                                jlong handle,
                                                                                jstring chat_id,
                                                                                jbyteArray payload,
                                                                                jint content_type) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return;
  }
  std::string chat = toString(env, chat_id);
  std::vector<uint8_t> bytes = toBytes(env, payload);
  if (content_type == 1) {
    std::string text(bytes.begin(), bytes.end());
    instance->bridge->send(chat, text);
    return;
  }
  instance->bridge->send(chat, bytes);
}

extern "C" JNIEXPORT jstring JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeGetHistoryJson(JNIEnv* env,
                                                                                              jclass,
                                                                                              jlong handle,
                                                                                              jstring chat_id,
                                                                                              jlong cursor,
                                                                                              jint limit) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return env->NewStringUTF("[]");
  }
  std::string chat = toString(env, chat_id);
  std::vector<bridge::HistoryMessage> history = instance->bridge->getHistory(chat, cursor, static_cast<size_t>(limit));
  std::string json = historyToJson(history);
  return env->NewStringUTF(json.c_str());
}

extern "C" JNIEXPORT void JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeLinkDevice(JNIEnv* env,
                                                                                       jclass,
                                                                                       jlong handle,
                                                                                       jstring link_code) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return;
  }
  std::string code = toString(env, link_code);
  instance->bridge->linkDevice(code);
}

extern "C" JNIEXPORT void JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeUpdateProfile(JNIEnv* env,
                                                                                           jclass,
                                                                                           jlong handle,
                                                                                           jstring username,
                                                                                           jstring password) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return;
  }
  std::string name = toString(env, username);
  std::string pass = toString(env, password);
  instance->bridge->updateProfile(name, pass);
}

extern "C" JNIEXPORT void JNICALL Java_com_p2pchat_bridge_BridgeModule_nativeConnectPeer(JNIEnv* env,
                                                                                        jclass,
                                                                                        jlong handle,
                                                                                        jstring peer_id,
                                                                                        jstring address,
                                                                                        jint port,
                                                                                        jstring ice_blob) {
  auto* instance = fromHandle(handle);
  if (!instance) {
    return;
  }
  bridge::PeerInfo info;
  info.peer_id = toString(env, peer_id);
  info.address = toString(env, address);
  info.port = static_cast<uint16_t>(port);
  info.ice_blob = toString(env, ice_blob);
  instance->bridge->connectPeer(info);
}
