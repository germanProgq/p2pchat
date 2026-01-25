// C FFI surface for desktop UI bindings. Spec: docs/desktop_app.md.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct p2pchat_handle p2pchat_handle;

typedef enum {
  P2PCHAT_EVENT_MESSAGE = 1,
  P2PCHAT_EVENT_CONNECTION = 2,
  P2PCHAT_EVENT_PEER_STATUS = 3,
  P2PCHAT_EVENT_ERROR = 4
} p2pchat_event_type;

typedef enum {
  P2PCHAT_TRANSPORT_LOOPBACK = 1,
  P2PCHAT_TRANSPORT_QUIC = 2,
  P2PCHAT_TRANSPORT_WEBRTC = 3
} p2pchat_transport_kind;

typedef struct {
  uint8_t type;
  const char* address;
  uint16_t port;
  uint32_t priority;
} p2pchat_relay_candidate;

typedef struct {
  const char* identity_path;
  const char* storage_path;
  const char* schema_path;
  const char* username;
  const char* password;
  const uint8_t* master_key;
  size_t master_key_len;
  const char* keystore_service;

  uint8_t transport_kind;
  size_t max_in_flight;
  size_t max_queue_bytes;
  int64_t retry_base_delay_ms;
  int64_t retry_max_delay_ms;
  uint32_t retry_max_attempts;
  double retry_jitter_ratio;

  const char* bind_address;
  uint16_t bind_port;
  size_t max_datagram_size;

  const char** stun_servers;
  size_t stun_server_count;
  const p2pchat_relay_candidate* relay_candidates;
  size_t relay_candidate_count;

  size_t one_time_prekeys;
  uint32_t signed_prekey_id;
  uint32_t one_time_start_id;
  int64_t handshake_base_delay_ms;
  int64_t handshake_max_delay_ms;
  uint32_t handshake_max_attempts;

  void* loopback_network;
} p2pchat_node_config;

typedef struct {
  const char* peer_id;
  const char* address;
  uint16_t port;
  const char* ice_blob;
} p2pchat_peer_info;

typedef void (*p2pchat_event_cb)(void* user_data,
                                 p2pchat_event_type event_type,
                                 const char* payload_json);

p2pchat_handle* p2pchat_create();
void p2pchat_destroy(p2pchat_handle* handle);

void p2pchat_set_event_callback(p2pchat_handle* handle,
                                p2pchat_event_cb callback,
                                void* user_data);

bool p2pchat_start(p2pchat_handle* handle, const p2pchat_node_config* config);
void p2pchat_stop(p2pchat_handle* handle);
void p2pchat_tick(p2pchat_handle* handle, int64_t now_ms);

char* p2pchat_local_bundle_hex(p2pchat_handle* handle);
char* p2pchat_local_ice(p2pchat_handle* handle);
char* p2pchat_begin_link(p2pchat_handle* handle);

char* p2pchat_add_contact(p2pchat_handle* handle,
                          const uint8_t* bundle_bytes,
                          size_t bundle_len);

char* p2pchat_add_contact_with_username(p2pchat_handle* handle,
                                        const uint8_t* bundle_bytes,
                                        size_t bundle_len,
                                        const char* username);

bool p2pchat_connect_peer(p2pchat_handle* handle, const p2pchat_peer_info* peer);

bool p2pchat_send(p2pchat_handle* handle,
                  const char* chat_id,
                  const uint8_t* payload,
                  size_t payload_len,
                  uint8_t content_type);

char* p2pchat_get_history_json(p2pchat_handle* handle,
                               const char* chat_id,
                               int64_t cursor,
                               size_t limit);

bool p2pchat_link_device(p2pchat_handle* handle, const char* link_code);

char* p2pchat_local_username(p2pchat_handle* handle);
char* p2pchat_identity_public_key_hex(p2pchat_handle* handle);
char* p2pchat_sign_identity_hex(p2pchat_handle* handle,
                                const uint8_t* message_bytes,
                                size_t message_len);
bool p2pchat_update_profile(p2pchat_handle* handle, const char* username, const char* password);

const char* p2pchat_last_error();
void p2pchat_clear_error();
void p2pchat_string_free(char* value);

#ifdef __cplusplus
}
#endif
