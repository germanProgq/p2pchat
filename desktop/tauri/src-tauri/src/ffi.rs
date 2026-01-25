// Rust FFI bindings for the desktop core adapter. Spec: docs/desktop_app.md.
use libloading::{Library, Symbol};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

#[repr(C)]
pub struct P2pchatHandle {
  _private: [u8; 0],
}

unsafe impl Send for P2pchatHandle {}
unsafe impl Sync for P2pchatHandle {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RelayCandidate {
  pub r#type: u8,
  pub address: *const c_char,
  pub port: u16,
  pub priority: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct NodeConfig {
  pub identity_path: *const c_char,
  pub storage_path: *const c_char,
  pub schema_path: *const c_char,
  pub username: *const c_char,
  pub password: *const c_char,
  pub master_key: *const u8,
  pub master_key_len: usize,
  pub keystore_service: *const c_char,

  pub transport_kind: u8,
  pub max_in_flight: usize,
  pub max_queue_bytes: usize,
  pub retry_base_delay_ms: i64,
  pub retry_max_delay_ms: i64,
  pub retry_max_attempts: u32,
  pub retry_jitter_ratio: f64,

  pub bind_address: *const c_char,
  pub bind_port: u16,
  pub max_datagram_size: usize,

  pub stun_servers: *const *const c_char,
  pub stun_server_count: usize,
  pub relay_candidates: *const RelayCandidate,
  pub relay_candidate_count: usize,

  pub one_time_prekeys: usize,
  pub signed_prekey_id: u32,
  pub one_time_start_id: u32,
  pub handshake_base_delay_ms: i64,
  pub handshake_max_delay_ms: i64,
  pub handshake_max_attempts: u32,

  pub loopback_network: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PeerInfo {
  pub peer_id: *const c_char,
  pub address: *const c_char,
  pub port: u16,
  pub ice_blob: *const c_char,
}

pub type EventCallback = unsafe extern "C" fn(*mut c_void, u32, *const c_char);

pub struct FfiApi {
  _lib: Library,
  pub create: unsafe extern "C" fn() -> *mut P2pchatHandle,
  pub destroy: unsafe extern "C" fn(*mut P2pchatHandle),
  pub set_event_callback: unsafe extern "C" fn(*mut P2pchatHandle, EventCallback, *mut c_void),
  pub start: unsafe extern "C" fn(*mut P2pchatHandle, *const NodeConfig) -> bool,
  pub stop: unsafe extern "C" fn(*mut P2pchatHandle),
  pub tick: unsafe extern "C" fn(*mut P2pchatHandle, i64),
  pub local_bundle_hex: unsafe extern "C" fn(*mut P2pchatHandle) -> *mut c_char,
  pub local_ice: unsafe extern "C" fn(*mut P2pchatHandle) -> *mut c_char,
  pub begin_link: unsafe extern "C" fn(*mut P2pchatHandle) -> *mut c_char,
  pub add_contact: unsafe extern "C" fn(*mut P2pchatHandle, *const u8, usize) -> *mut c_char,
  pub add_contact_with_username: unsafe extern "C" fn(*mut P2pchatHandle, *const u8, usize, *const c_char) -> *mut c_char,
  pub connect_peer: unsafe extern "C" fn(*mut P2pchatHandle, *const PeerInfo) -> bool,
  pub send: unsafe extern "C" fn(*mut P2pchatHandle, *const c_char, *const u8, usize, u8) -> bool,
  pub get_history_json: unsafe extern "C" fn(*mut P2pchatHandle, *const c_char, i64, usize) -> *mut c_char,
  pub link_device: unsafe extern "C" fn(*mut P2pchatHandle, *const c_char) -> bool,
  pub local_username: unsafe extern "C" fn(*mut P2pchatHandle) -> *mut c_char,
  pub identity_public_key_hex: unsafe extern "C" fn(*mut P2pchatHandle) -> *mut c_char,
  pub sign_identity_hex: unsafe extern "C" fn(*mut P2pchatHandle, *const u8, usize) -> *mut c_char,
  pub update_profile: unsafe extern "C" fn(*mut P2pchatHandle, *const c_char, *const c_char) -> bool,
  pub last_error: unsafe extern "C" fn() -> *const c_char,
  pub clear_error: unsafe extern "C" fn(),
  pub string_free: unsafe extern "C" fn(*mut c_char),
}

impl FfiApi {
  unsafe fn load_symbol<T: Copy>(lib: &Library, name: &[u8]) -> Result<T, String> {
    let symbol: Symbol<T> = lib.get(name).map_err(|e| e.to_string())?;
    Ok(*symbol)
  }

  pub unsafe fn load(path: &str) -> Result<Self, String> {
    let lib = Library::new(path).map_err(|err| err.to_string())?;
    let create = Self::load_symbol::<unsafe extern "C" fn() -> *mut P2pchatHandle>(&lib, b"p2pchat_create\0")?;
    let destroy = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle)>(&lib, b"p2pchat_destroy\0")?;
    let set_event_callback = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, EventCallback, *mut c_void)>(
      &lib,
      b"p2pchat_set_event_callback\0",
    )?;
    let start = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, *const NodeConfig) -> bool>(
      &lib,
      b"p2pchat_start\0",
    )?;
    let stop = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle)>(&lib, b"p2pchat_stop\0")?;
    let tick = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, i64)>(&lib, b"p2pchat_tick\0")?;
    let local_bundle_hex = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle) -> *mut c_char>(
      &lib,
      b"p2pchat_local_bundle_hex\0",
    )?;
    let local_ice = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle) -> *mut c_char>(
      &lib,
      b"p2pchat_local_ice\0",
    )?;
    let begin_link = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle) -> *mut c_char>(
      &lib,
      b"p2pchat_begin_link\0",
    )?;
    let add_contact = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, *const u8, usize) -> *mut c_char>(
      &lib,
      b"p2pchat_add_contact\0",
    )?;
    let add_contact_with_username = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, *const u8, usize, *const c_char) -> *mut c_char>(
      &lib,
      b"p2pchat_add_contact_with_username\0",
    )?;
    let connect_peer = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, *const PeerInfo) -> bool>(
      &lib,
      b"p2pchat_connect_peer\0",
    )?;
    let send = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, *const c_char, *const u8, usize, u8) -> bool>(
      &lib,
      b"p2pchat_send\0",
    )?;
    let get_history_json = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, *const c_char, i64, usize) -> *mut c_char>(
      &lib,
      b"p2pchat_get_history_json\0",
    )?;
    let link_device = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, *const c_char) -> bool>(
      &lib,
      b"p2pchat_link_device\0",
    )?;
    let local_username = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle) -> *mut c_char>(
      &lib,
      b"p2pchat_local_username\0",
    )?;
    let identity_public_key_hex = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle) -> *mut c_char>(
      &lib,
      b"p2pchat_identity_public_key_hex\0",
    )?;
    let sign_identity_hex = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, *const u8, usize) -> *mut c_char>(
      &lib,
      b"p2pchat_sign_identity_hex\0",
    )?;
    let update_profile = Self::load_symbol::<unsafe extern "C" fn(*mut P2pchatHandle, *const c_char, *const c_char) -> bool>(
      &lib,
      b"p2pchat_update_profile\0",
    )?;
    let last_error = Self::load_symbol::<unsafe extern "C" fn() -> *const c_char>(&lib, b"p2pchat_last_error\0")?;
    let clear_error = Self::load_symbol::<unsafe extern "C" fn()>(&lib, b"p2pchat_clear_error\0")?;
    let string_free = Self::load_symbol::<unsafe extern "C" fn(*mut c_char)>(&lib, b"p2pchat_string_free\0")?;

    Ok(Self {
      _lib: lib,
      create,
      destroy,
      set_event_callback,
      start,
      stop,
      tick,
      local_bundle_hex,
      local_ice,
      begin_link,
      add_contact,
      add_contact_with_username,
      connect_peer,
      send,
      get_history_json,
      link_device,
      local_username,
      identity_public_key_hex,
      sign_identity_hex,
      update_profile,
      last_error,
      clear_error,
      string_free,
    })
  }

  pub unsafe fn error_message(&self) -> Option<String> {
    let ptr = (self.last_error)();
    if ptr.is_null() {
      return None;
    }
    let message = CStr::from_ptr(ptr).to_string_lossy().to_string();
    (self.clear_error)();
    Some(message)
  }

  pub unsafe fn take_string(&self, ptr: *mut c_char) -> Option<String> {
    if ptr.is_null() {
      return None;
    }
    let value = CStr::from_ptr(ptr).to_string_lossy().to_string();
    (self.string_free)(ptr);
    Some(value)
  }

  pub fn to_cstring(value: &str) -> CString {
    CString::new(value).unwrap_or_else(|_| CString::new("").unwrap())
  }
}
