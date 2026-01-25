// iOS TurboModule implementation for Bridge. Spec: app/bridge/BridgeSpec.md.
#import <Foundation/Foundation.h>
#import <React/RCTBridgeModule.h>
#import <React/RCTEventEmitter.h>
#import <React/RCTTurboModule.h>

#include <memory>
#include <string>
#include <vector>

#include "bridge/Bridge.h"

namespace {

NSString *contentTypeToString(bridge::ContentType type) {
  switch (type) {
    case bridge::ContentType::Text:
      return @"text";
    case bridge::ContentType::Binary:
      return @"binary";
  }
  return @"binary";
}

NSString *connectionStateToString(bridge::ConnectionState state) {
  switch (state) {
    case bridge::ConnectionState::Disconnected:
      return @"disconnected";
    case bridge::ConnectionState::Connecting:
      return @"connecting";
    case bridge::ConnectionState::Connected:
      return @"connected";
  }
  return @"disconnected";
}

NSString *peerStatusToString(bridge::PeerStatus status) {
  switch (status) {
    case bridge::PeerStatus::Pending:
      return @"pending";
    case bridge::PeerStatus::Ready:
      return @"ready";
    case bridge::PeerStatus::Failed:
      return @"failed";
  }
  return @"failed";
}

std::vector<uint8_t> bytesFromObject(id value) {
  if (!value || value == [NSNull null]) {
    return {};
  }
  if ([value isKindOfClass:[NSData class]]) {
    NSData *data = (NSData *)value;
    const uint8_t *bytes = (const uint8_t *)data.bytes;
    return std::vector<uint8_t>(bytes, bytes + data.length);
  }
  if ([value isKindOfClass:[NSArray class]]) {
    NSArray *array = (NSArray *)value;
    std::vector<uint8_t> out;
    out.reserve(array.count);
    for (NSNumber *number in array) {
      out.push_back((uint8_t)number.intValue);
    }
    return out;
  }
  if ([value isKindOfClass:[NSString class]]) {
    NSData *data = [[NSData alloc] initWithBase64EncodedString:(NSString *)value options:0];
    if (data) {
      const uint8_t *bytes = (const uint8_t *)data.bytes;
      return std::vector<uint8_t>(bytes, bytes + data.length);
    }
  }
  return {};
}

NSArray *byteArrayFromVector(const std::vector<uint8_t> &bytes) {
  NSMutableArray *array = [NSMutableArray arrayWithCapacity:bytes.size()];
  for (uint8_t value : bytes) {
    [array addObject:@(value)];
  }
  return array;
}

bridge::TransportKind transportKindFromString(NSString *value) {
  if ([value isEqualToString:@"webrtc"]) {
    return bridge::TransportKind::WebRtc;
  }
  if ([value isEqualToString:@"loopback"]) {
    return bridge::TransportKind::Loopback;
  }
  return bridge::TransportKind::Quic;
}

const char *requireCString(NSDictionary *config, NSString *key) {
  id value = [config objectForKey:key];
  if (![value isKindOfClass:[NSString class]]) {
    @throw [NSException exceptionWithName:@"BridgeConfigError"
                                   reason:[NSString stringWithFormat:@"Missing required field: %@", key]
                                 userInfo:nil];
  }
  NSString *text = (NSString *)value;
  if (text.length == 0) {
    @throw [NSException exceptionWithName:@"BridgeConfigError"
                                   reason:[NSString stringWithFormat:@"Empty required field: %@", key]
                                 userInfo:nil];
  }
  return [text UTF8String];
}

bridge::NodeConfig parseNodeConfig(NSDictionary *config) {
  bridge::NodeConfig out;
  out.identity_path = requireCString(config, @"identityPath");
  out.storage_path = requireCString(config, @"storagePath");
  out.schema_path = requireCString(config, @"schemaPath");
  NSString *username = [config objectForKey:@"username"];
  NSString *password = [config objectForKey:@"password"];
  if (username) {
    out.username = [username UTF8String];
  }
  if (password) {
    out.password = [password UTF8String];
  }
  id masterKey = [config objectForKey:@"masterKey"];
  out.master_key = bytesFromObject(masterKey);

  NSString *transportKind = [config objectForKey:@"transportKind"];
  if (transportKind) {
    out.transport_kind = transportKindFromString(transportKind);
  }

  NSDictionary *transport = [config objectForKey:@"transport"];
  if (transport) {
    NSNumber *maxInFlight = [transport objectForKey:@"maxInFlight"];
    NSNumber *maxQueueBytes = [transport objectForKey:@"maxQueueBytes"];
    if (maxInFlight) {
      out.transport.max_in_flight = maxInFlight.unsignedIntegerValue;
    }
    if (maxQueueBytes) {
      out.transport.max_queue_bytes = maxQueueBytes.unsignedIntegerValue;
    }
    NSDictionary *retry = [transport objectForKey:@"retry"];
    if (retry) {
      NSNumber *baseDelay = [retry objectForKey:@"baseDelayMs"];
      NSNumber *maxDelay = [retry objectForKey:@"maxDelayMs"];
      NSNumber *maxAttempts = [retry objectForKey:@"maxAttempts"];
      NSNumber *jitterRatio = [retry objectForKey:@"jitterRatio"];
      if (baseDelay) {
        out.transport.retry.base_delay_ms = baseDelay.longLongValue;
      }
      if (maxDelay) {
        out.transport.retry.max_delay_ms = maxDelay.longLongValue;
      }
      if (maxAttempts) {
        out.transport.retry.max_attempts = maxAttempts.unsignedIntValue;
      }
      if (jitterRatio) {
        out.transport.retry.jitter_ratio = jitterRatio.doubleValue;
      }
    }
  }

  auto parseIce = ^(NSDictionary *ice, transport::IceConfig &iceConfig) {
    if (!ice) {
      return;
    }
    NSArray *stunServers = [ice objectForKey:@"stunServers"];
    if (stunServers) {
      iceConfig.stun_servers.clear();
      for (NSString *server in stunServers) {
        iceConfig.stun_servers.push_back([server UTF8String]);
      }
    }
    NSString *bindAddress = [ice objectForKey:@"bindAddress"];
    if (bindAddress) {
      iceConfig.bind_address = [bindAddress UTF8String];
    }
    NSNumber *bindPort = [ice objectForKey:@"bindPort"];
    if (bindPort) {
      iceConfig.bind_port = bindPort.unsignedIntValue;
    }
    NSNumber *timeoutMs = [ice objectForKey:@"timeoutMs"];
    if (timeoutMs) {
      iceConfig.timeout_ms = timeoutMs.intValue;
    }
    NSArray *relayCandidates = [ice objectForKey:@"relayCandidates"];
    if (relayCandidates) {
      iceConfig.relay_candidates.clear();
      for (NSDictionary *candidate in relayCandidates) {
        NSNumber *type = [candidate objectForKey:@"type"];
        NSString *address = [candidate objectForKey:@"address"];
        NSNumber *port = [candidate objectForKey:@"port"];
        NSNumber *priority = [candidate objectForKey:@"priority"];
        transport::IceCandidate entry;
        entry.type = static_cast<transport::IceCandidateType>(type ? type.unsignedCharValue : 3);
        entry.address = address ? [address UTF8String] : "";
        entry.port = port ? port.unsignedShortValue : 0;
        entry.priority = priority ? priority.unsignedIntValue : 0;
        iceConfig.relay_candidates.push_back(entry);
      }
    }
  };

  NSDictionary *quic = [config objectForKey:@"quic"];
  if (quic) {
    NSString *bindAddress = [quic objectForKey:@"bindAddress"];
    NSNumber *bindPort = [quic objectForKey:@"bindPort"];
    NSNumber *maxDatagram = [quic objectForKey:@"maxDatagramSize"];
    if (bindAddress) {
      out.quic.bind_address = [bindAddress UTF8String];
    }
    if (bindPort) {
      out.quic.bind_port = bindPort.unsignedShortValue;
    }
    if (maxDatagram) {
      out.quic.max_datagram_size = maxDatagram.unsignedIntegerValue;
    }
    parseIce([quic objectForKey:@"ice"], out.quic.ice);
  }

  NSDictionary *webrtc = [config objectForKey:@"webrtc"];
  if (webrtc) {
    NSString *bindAddress = [webrtc objectForKey:@"bindAddress"];
    NSNumber *bindPort = [webrtc objectForKey:@"bindPort"];
    NSNumber *maxDatagram = [webrtc objectForKey:@"maxDatagramSize"];
    if (bindAddress) {
      out.webrtc.bind_address = [bindAddress UTF8String];
    }
    if (bindPort) {
      out.webrtc.bind_port = bindPort.unsignedShortValue;
    }
    if (maxDatagram) {
      out.webrtc.max_datagram_size = maxDatagram.unsignedIntegerValue;
    }
    parseIce([webrtc objectForKey:@"ice"], out.webrtc.ice);
  }

  NSNumber *oneTimePrekeys = [config objectForKey:@"oneTimePrekeys"];
  NSNumber *signedPrekeyId = [config objectForKey:@"signedPrekeyId"];
  NSNumber *oneTimeStartId = [config objectForKey:@"oneTimeStartId"];
  NSNumber *handshakeBaseDelayMs = [config objectForKey:@"handshakeBaseDelayMs"];
  NSNumber *handshakeMaxDelayMs = [config objectForKey:@"handshakeMaxDelayMs"];
  NSNumber *handshakeMaxAttempts = [config objectForKey:@"handshakeMaxAttempts"];

  if (oneTimePrekeys) {
    out.one_time_prekeys = oneTimePrekeys.unsignedIntegerValue;
  }
  if (signedPrekeyId) {
    out.signed_prekey_id = signedPrekeyId.unsignedIntValue;
  }
  if (oneTimeStartId) {
    out.one_time_start_id = oneTimeStartId.unsignedIntValue;
  }
  if (handshakeBaseDelayMs) {
    out.handshake_base_delay_ms = handshakeBaseDelayMs.longLongValue;
  }
  if (handshakeMaxDelayMs) {
    out.handshake_max_delay_ms = handshakeMaxDelayMs.longLongValue;
  }
  if (handshakeMaxAttempts) {
    out.handshake_max_attempts = handshakeMaxAttempts.unsignedIntValue;
  }

  return out;
}

NSDictionary *incomingToDict(const bridge::IncomingMessage &message) {
  return @{
    @"chatId": [NSString stringWithUTF8String:message.chat_id.c_str()],
    @"msgId": [NSString stringWithUTF8String:message.msg_id.c_str()],
    @"senderDevice": [NSString stringWithUTF8String:message.sender_device.c_str()],
    @"peerUsername": [NSString stringWithUTF8String:message.peer_username.c_str()],
    @"tsMs": @(message.ts_ms),
    @"contentType": contentTypeToString(message.content_type),
    @"body": byteArrayFromVector(message.body),
  };
}

NSDictionary *historyToDict(const bridge::HistoryMessage &message) {
  return @{
    @"chatId": [NSString stringWithUTF8String:message.chat_id.c_str()],
    @"msgId": [NSString stringWithUTF8String:message.msg_id.c_str()],
    @"senderDevice": [NSString stringWithUTF8String:message.sender_device.c_str()],
    @"peerUsername": [NSString stringWithUTF8String:message.peer_username.c_str()],
    @"tsMs": @(message.ts_ms),
    @"contentType": contentTypeToString(message.content_type),
    @"body": byteArrayFromVector(message.body),
    @"delivered": @(message.delivered),
    @"acked": @(message.acked),
    @"index": @(message.index),
  };
}

NSDictionary *connectionToDict(const bridge::ConnectionEvent &event) {
  return @{
    @"peerId": [NSString stringWithUTF8String:event.peer_id.c_str()],
    @"peerUsername": [NSString stringWithUTF8String:event.peer_username.c_str()],
    @"state": connectionStateToString(event.state),
  };
}

NSDictionary *statusToDict(const bridge::PeerStatusEvent &event) {
  return @{
    @"peerId": [NSString stringWithUTF8String:event.peer_id.c_str()],
    @"peerUsername": [NSString stringWithUTF8String:event.peer_username.c_str()],
    @"status": peerStatusToString(event.status),
  };
}

NSDictionary *errorToDict(const bridge::ErrorEvent &event) {
  return @{
    @"peerId": [NSString stringWithUTF8String:event.peer_id.c_str()],
    @"peerUsername": [NSString stringWithUTF8String:event.peer_username.c_str()],
    @"message": [NSString stringWithUTF8String:event.message.c_str()],
  };
}

}

@interface BridgeModule : RCTEventEmitter <RCTBridgeModule, RCTTurboModule>
@end

@implementation BridgeModule {
  std::shared_ptr<bridge::CoreAdapter> _backend;
  std::unique_ptr<bridge::Bridge> _bridge;
  NSInteger _listenerCount;
}

RCT_EXPORT_MODULE(Bridge)

- (instancetype)init {
  if ((self = [super init])) {
    _backend = std::make_shared<bridge::CoreAdapter>();
    _bridge = std::make_unique<bridge::Bridge>(_backend);
    _listenerCount = 0;

    __weak BridgeModule *weakSelf = self;
    _bridge->onMessage = [weakSelf](const bridge::IncomingMessage &message) {
      BridgeModule *strongSelf = weakSelf;
      if (!strongSelf || strongSelf->_listenerCount <= 0) {
        return;
      }
      [strongSelf sendEventWithName:@"onMessage" body:incomingToDict(message)];
    };
    _bridge->onConnectionChange = [weakSelf](const bridge::ConnectionEvent &event) {
      BridgeModule *strongSelf = weakSelf;
      if (!strongSelf || strongSelf->_listenerCount <= 0) {
        return;
      }
      [strongSelf sendEventWithName:@"onConnectionChange" body:connectionToDict(event)];
    };
    _bridge->onPeerStatus = [weakSelf](const bridge::PeerStatusEvent &event) {
      BridgeModule *strongSelf = weakSelf;
      if (!strongSelf || strongSelf->_listenerCount <= 0) {
        return;
      }
      [strongSelf sendEventWithName:@"onPeerStatus" body:statusToDict(event)];
    };
    _bridge->onError = [weakSelf](const bridge::ErrorEvent &event) {
      BridgeModule *strongSelf = weakSelf;
      if (!strongSelf || strongSelf->_listenerCount <= 0) {
        return;
      }
      [strongSelf sendEventWithName:@"onError" body:errorToDict(event)];
    };
  }
  return self;
}

- (NSArray<NSString *> *)supportedEvents {
  return @[ @"onMessage", @"onConnectionChange", @"onPeerStatus", @"onError" ];
}

RCT_EXPORT_METHOD(start:(NSDictionary *)config) {
  bridge::NodeConfig parsed = parseNodeConfig(config);
  _bridge->start(parsed);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(localBundle) {
  std::vector<uint8_t> bytes = _bridge->localBundle();
  if (bytes.empty()) {
    return [NSData data];
  }
  return [NSData dataWithBytes:bytes.data() length:bytes.size()];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(localIce) {
  std::string ice = _bridge->localIce();
  return [NSString stringWithUTF8String:ice.c_str()];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(beginLink) {
  std::string code = _bridge->beginLink();
  return [NSString stringWithUTF8String:code.c_str()];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(addContact:(id)prekeyBundle) {
  std::vector<uint8_t> bytes = bytesFromObject(prekeyBundle);
  std::string peerId = _bridge->addContact(bytes);
  return [NSString stringWithUTF8String:peerId.c_str()];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(addContactWithUsername:(id)prekeyBundle username:(NSString *)username) {
  std::vector<uint8_t> bytes = bytesFromObject(prekeyBundle);
  std::string name = username ? [username UTF8String] : "";
  std::string peerId = _bridge->addContactWithUsername(bytes, name);
  return [NSString stringWithUTF8String:peerId.c_str()];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(localUsername) {
  std::string name = _bridge->localUsername();
  return [NSString stringWithUTF8String:name.c_str()];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(localIdentityPublicKey) {
  std::vector<uint8_t> key = _bridge->localIdentityPublicKey();
  if (key.empty()) {
    return [NSData data];
  }
  return [NSData dataWithBytes:key.data() length:key.size()];
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(signIdentity:(id)message) {
  std::vector<uint8_t> bytes = bytesFromObject(message);
  std::vector<uint8_t> sig = _bridge->signIdentity(bytes);
  if (sig.empty()) {
    return [NSData data];
  }
  return [NSData dataWithBytes:sig.data() length:sig.size()];
}

RCT_EXPORT_METHOD(connectPeer:(NSDictionary *)peerInfo) {
  if (!peerInfo) {
    return;
  }
  bridge::PeerInfo info;
  NSString *peerId = [peerInfo objectForKey:@"peerId"];
  NSString *address = [peerInfo objectForKey:@"address"];
  NSNumber *port = [peerInfo objectForKey:@"port"];
  NSString *iceBlob = [peerInfo objectForKey:@"iceBlob"];
  if (peerId) {
    info.peer_id = [peerId UTF8String];
  }
  if (address) {
    info.address = [address UTF8String];
  }
  if (port) {
    info.port = port.unsignedShortValue;
  }
  if (iceBlob) {
    info.ice_blob = [iceBlob UTF8String];
  }
  _bridge->connectPeer(info);
}

RCT_EXPORT_METHOD(send:(NSString *)chatId payload:(id)payload) {
  if (!payload) {
    return;
  }
  if ([payload isKindOfClass:[NSString class]]) {
    std::string chat([chatId UTF8String]);
    std::string message([(NSString *)payload UTF8String]);
    _bridge->send(chat, message);
    return;
  }
  std::vector<uint8_t> bytes = bytesFromObject(payload);
  if (bytes.empty()) {
    @throw [NSException exceptionWithName:@"BridgePayloadError"
                                   reason:@"Binary payload is empty"
                                 userInfo:nil];
  }
  _bridge->send([chatId UTF8String], bytes);
}

RCT_EXPORT_BLOCKING_SYNCHRONOUS_METHOD(getHistory:(NSString *)chatId cursor:(double)cursor limit:(double)limit) {
  std::vector<bridge::HistoryMessage> history = _bridge->getHistory([chatId UTF8String], static_cast<int64_t>(cursor), static_cast<size_t>(limit));
  NSMutableArray *array = [NSMutableArray arrayWithCapacity:history.size()];
  for (const auto &message : history) {
    [array addObject:historyToDict(message)];
  }
  return array;
}

RCT_EXPORT_METHOD(linkDevice:(NSString *)linkCode) {
  _bridge->linkDevice([linkCode UTF8String]);
}

RCT_EXPORT_METHOD(updateProfile:(NSString *)username password:(NSString *)password) {
  std::string name = username ? [username UTF8String] : "";
  std::string pass = password ? [password UTF8String] : "";
  _bridge->updateProfile(name, pass);
}

RCT_EXPORT_METHOD(addListener:(NSString *)eventName) {
  _listenerCount += 1;
}

RCT_EXPORT_METHOD(removeListeners:(double)count) {
  NSInteger remove = (NSInteger)count;
  _listenerCount = MAX(0, _listenerCount - remove);
}

@end
