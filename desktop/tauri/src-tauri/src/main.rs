// Tauri desktop backend wiring to core FFI. Spec: docs/desktop_app.md.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::ffi::{c_char, c_void, CString};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, State};

mod ffi;

use ffi::{EventCallback, FfiApi, NodeConfig, PeerInfo, RelayCandidate};

static EVENT_SENDER: OnceLock<mpsc::Sender<CoreEvent>> = OnceLock::new();

#[derive(Clone, Debug, Serialize)]
struct CoreEvent {
  event: String,
  payload: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UiConfig {
  data_dir: Option<String>,
  identity_path: Option<String>,
  storage_path: Option<String>,
  schema_path: Option<String>,
  username: Option<String>,
  password: Option<String>,
  transport_kind: Option<String>,
  bind_address: Option<String>,
  bind_port: Option<u16>,
  max_datagram_size: Option<usize>,
  max_in_flight: Option<usize>,
  max_queue_bytes: Option<usize>,
  retry_base_delay_ms: Option<i64>,
  retry_max_delay_ms: Option<i64>,
  retry_max_attempts: Option<u32>,
  retry_jitter_ratio: Option<f64>,
  stun_servers: Option<Vec<String>>,
  relay_candidates: Option<Vec<UiRelayCandidate>>,
  one_time_prekeys: Option<usize>,
  signed_prekey_id: Option<u32>,
  one_time_start_id: Option<u32>,
  handshake_base_delay_ms: Option<i64>,
  handshake_max_delay_ms: Option<i64>,
  handshake_max_attempts: Option<u32>,
  tick_interval_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UiRelayCandidate {
  r#type: u8,
  address: String,
  port: u16,
  priority: u32,
}

struct ConfigStore {
  identity_path: CString,
  storage_path: CString,
  schema_path: CString,
  username: CString,
  password: CString,
  keystore_service: CString,
  bind_address: CString,
  _stun_servers: Vec<CString>,
  _relay_addresses: Vec<CString>,
  stun_server_ptrs: Vec<*const c_char>,
  relay_candidates: Vec<RelayCandidate>,
  transport_kind: u8,
  max_in_flight: usize,
  max_queue_bytes: usize,
  retry_base_delay_ms: i64,
  retry_max_delay_ms: i64,
  retry_max_attempts: u32,
  retry_jitter_ratio: f64,
  bind_port: u16,
  max_datagram_size: usize,
  one_time_prekeys: usize,
  signed_prekey_id: u32,
  one_time_start_id: u32,
  handshake_base_delay_ms: i64,
  handshake_max_delay_ms: i64,
  handshake_max_attempts: u32,
}

impl ConfigStore {
  fn to_node_config(&self) -> NodeConfig {
    NodeConfig {
      identity_path: self.identity_path.as_ptr(),
      storage_path: self.storage_path.as_ptr(),
      schema_path: self.schema_path.as_ptr(),
      username: self.username.as_ptr(),
      password: self.password.as_ptr(),
      master_key: std::ptr::null(),
      master_key_len: 0,
      keystore_service: self.keystore_service.as_ptr(),

      transport_kind: self.transport_kind,
      max_in_flight: self.max_in_flight,
      max_queue_bytes: self.max_queue_bytes,
      retry_base_delay_ms: self.retry_base_delay_ms,
      retry_max_delay_ms: self.retry_max_delay_ms,
      retry_max_attempts: self.retry_max_attempts,
      retry_jitter_ratio: self.retry_jitter_ratio,

      bind_address: self.bind_address.as_ptr(),
      bind_port: self.bind_port,
      max_datagram_size: self.max_datagram_size,

      stun_servers: self.stun_server_ptrs.as_ptr(),
      stun_server_count: self.stun_server_ptrs.len(),
      relay_candidates: self.relay_candidates.as_ptr(),
      relay_candidate_count: self.relay_candidates.len(),

      one_time_prekeys: self.one_time_prekeys,
      signed_prekey_id: self.signed_prekey_id,
      one_time_start_id: self.one_time_start_id,
      handshake_base_delay_ms: self.handshake_base_delay_ms,
      handshake_max_delay_ms: self.handshake_max_delay_ms,
      handshake_max_attempts: self.handshake_max_attempts,

      loopback_network: std::ptr::null_mut(),
    }
  }
}

#[derive(Copy, Clone)]
struct HandlePtr(*mut ffi::P2pchatHandle);

unsafe impl Send for HandlePtr {}
unsafe impl Sync for HandlePtr {}

struct CoreRuntime {
  ffi: FfiApi,
  handle: HandlePtr,
  tick_stop: Arc<AtomicBool>,
  tick_thread: Option<thread::JoinHandle<()>>,
}

impl Drop for CoreRuntime {
  fn drop(&mut self) {
    self.tick_stop.store(true, Ordering::Relaxed);
    if let Some(thread) = self.tick_thread.take() {
      let _ = thread.join();
    }
    unsafe {
      (self.ffi.stop)(self.handle.0);
      (self.ffi.destroy)(self.handle.0);
    }
  }
}

struct AppState {
  runtime: Mutex<Option<CoreRuntime>>,
}

unsafe extern "C" fn core_event_callback(_user_data: *mut c_void, event_type: u32, payload_json: *const c_char) {
  if payload_json.is_null() {
    return;
  }
  let sender = match EVENT_SENDER.get() {
    Some(sender) => sender,
    None => return,
  };
  let payload = std::ffi::CStr::from_ptr(payload_json).to_string_lossy().to_string();
  let payload_value: serde_json::Value = serde_json::from_str(&payload).unwrap_or(serde_json::json!({"raw": payload}));
  let name = match event_type {
    1 => "onMessage",
    2 => "onConnectionChange",
    3 => "onPeerStatus",
    4 => "onError",
    _ => "unknown",
  };
  let event = CoreEvent {
    event: name.to_string(),
    payload: payload_value,
  };
  let _ = sender.send(event);
}

fn now_ms() -> i64 {
  let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_else(|_| Duration::from_secs(0));
  now.as_millis() as i64
}

fn resolve_repo_root() -> PathBuf {
  let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
  manifest
    .parent()
    .and_then(|p| p.parent())
    .and_then(|p| p.parent())
    .map(|p| p.to_path_buf())
    .unwrap_or_else(|| manifest.to_path_buf())
}

fn resolve_data_dir(app: &AppHandle, override_path: Option<String>) -> Result<PathBuf, String> {
  if let Some(path) = override_path {
    return Ok(PathBuf::from(path));
  }
  app.path_resolver()
    .app_data_dir()
    .ok_or_else(|| "unable to resolve app data dir".to_string())
}

fn resolve_schema_path(app: &AppHandle, override_path: Option<String>) -> PathBuf {
  if let Some(path) = override_path {
    return PathBuf::from(path);
  }
  if let Ok(env_path) = std::env::var("P2PCHAT_SCHEMA_PATH") {
    if !env_path.is_empty() {
      return PathBuf::from(env_path);
    }
  }
  if let Some(resource_dir) = app.path_resolver().resource_dir() {
    let candidate = resource_dir.join("schema.sql");
    if candidate.exists() {
      return candidate;
    }
  }
  let repo_root = resolve_repo_root();
  repo_root.join("core/storage/schema.sql")
}

fn resolve_ffi_path(app: &AppHandle) -> Result<String, String> {
  if let Ok(value) = std::env::var("P2PCHAT_FFI_PATH") {
    if !value.is_empty() {
      return Ok(value);
    }
  }
  let repo_root = resolve_repo_root();
  let mut candidates = Vec::new();
  #[cfg(target_os = "windows")]
  let lib_name = "p2pchat_ffi.dll";
  #[cfg(target_os = "macos")]
  let lib_name = "libp2pchat_ffi.dylib";
  #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
  let lib_name = "libp2pchat_ffi.so";

  candidates.push(repo_root.join("build").join(lib_name));
  if let Some(resource_dir) = app.path_resolver().resource_dir() {
    candidates.push(resource_dir.join(lib_name));
  }
  if let Ok(exe) = std::env::current_exe() {
    if let Some(dir) = exe.parent() {
      candidates.push(dir.join(lib_name));
      candidates.push(dir.join("..").join("lib").join(lib_name));
    }
  }

  for candidate in candidates {
    if candidate.exists() {
      return Ok(candidate.to_string_lossy().to_string());
    }
  }
  Err("ffi library not found; set P2PCHAT_FFI_PATH".to_string())
}

fn build_config(app: &AppHandle, config: UiConfig) -> Result<(ConfigStore, u64), String> {
  let data_dir = resolve_data_dir(app, config.data_dir.clone())?;
  std::fs::create_dir_all(&data_dir).map_err(|e| e.to_string())?;

  let identity_path = config.identity_path.unwrap_or_else(|| data_dir.join("identity.bin").to_string_lossy().to_string());
  let storage_path = config.storage_path.unwrap_or_else(|| data_dir.join("store.db").to_string_lossy().to_string());
  let schema_path = resolve_schema_path(app, config.schema_path).to_string_lossy().to_string();

  let bind_address = config.bind_address.unwrap_or_else(|| "0.0.0.0".to_string());
  let keystore_service = CString::new("p2pchat").unwrap();
  let identity_path_c = CString::new(identity_path).map_err(|e| e.to_string())?;
  let storage_path_c = CString::new(storage_path).map_err(|e| e.to_string())?;
  let schema_path_c = CString::new(schema_path).map_err(|e| e.to_string())?;
  let username_c = CString::new(config.username.unwrap_or_default()).map_err(|e| e.to_string())?;
  let password_c = CString::new(config.password.unwrap_or_default()).map_err(|e| e.to_string())?;
  let bind_address_c = CString::new(bind_address).map_err(|e| e.to_string())?;

  let mut stun_servers = Vec::new();
  let mut stun_server_ptrs = Vec::new();
  if let Some(servers) = config.stun_servers {
    for server in servers {
      if let Ok(cstr) = CString::new(server) {
        stun_server_ptrs.push(cstr.as_ptr());
        stun_servers.push(cstr);
      }
    }
  }

  let mut relay_addresses = Vec::new();
  let mut relay_candidates = Vec::new();
  if let Some(relays) = config.relay_candidates {
    for relay in relays {
      if let Ok(address) = CString::new(relay.address) {
        relay_candidates.push(RelayCandidate {
          r#type: relay.r#type,
          address: address.as_ptr(),
          port: relay.port,
          priority: relay.priority,
        });
        relay_addresses.push(address);
      }
    }
  }

  let transport_kind = match config.transport_kind.as_deref() {
    Some("loopback") => 1,
    Some("webrtc") => 3,
    _ => 2,
  };

  let tick_interval = config.tick_interval_ms.unwrap_or(50);

  Ok((
    ConfigStore {
      identity_path: identity_path_c,
      storage_path: storage_path_c,
      schema_path: schema_path_c,
      username: username_c,
      password: password_c,
      keystore_service,
      bind_address: bind_address_c,
      _stun_servers: stun_servers,
      _relay_addresses: relay_addresses,
      stun_server_ptrs,
      relay_candidates,
      transport_kind,
      max_in_flight: config.max_in_flight.unwrap_or(0),
      max_queue_bytes: config.max_queue_bytes.unwrap_or(0),
      retry_base_delay_ms: config.retry_base_delay_ms.unwrap_or(0),
      retry_max_delay_ms: config.retry_max_delay_ms.unwrap_or(0),
      retry_max_attempts: config.retry_max_attempts.unwrap_or(0),
      retry_jitter_ratio: config.retry_jitter_ratio.unwrap_or(-1.0),
      bind_port: config.bind_port.unwrap_or(0),
      max_datagram_size: config.max_datagram_size.unwrap_or(0),
      one_time_prekeys: config.one_time_prekeys.unwrap_or(0),
      signed_prekey_id: config.signed_prekey_id.unwrap_or(0),
      one_time_start_id: config.one_time_start_id.unwrap_or(0),
      handshake_base_delay_ms: config.handshake_base_delay_ms.unwrap_or(0),
      handshake_max_delay_ms: config.handshake_max_delay_ms.unwrap_or(0),
      handshake_max_attempts: config.handshake_max_attempts.unwrap_or(0),
    },
    tick_interval,
  ))
}

fn hex_to_bytes(text: &str) -> Result<Vec<u8>, String> {
  let mut out = Vec::new();
  let clean = text.trim();
  if clean.len() % 2 != 0 {
    return Err("hex must have even length".to_string());
  }
  let bytes = clean.as_bytes();
  for i in (0..bytes.len()).step_by(2) {
    let hi = (bytes[i] as char).to_digit(16).ok_or_else(|| "invalid hex".to_string())?;
    let lo = (bytes[i + 1] as char).to_digit(16).ok_or_else(|| "invalid hex".to_string())?;
    out.push(((hi << 4) | lo) as u8);
  }
  Ok(out)
}

fn with_runtime<T, F>(state: &State<AppState>, f: F) -> Result<T, String>
where
  F: FnOnce(&mut CoreRuntime) -> Result<T, String>,
{
  let mut guard = state.runtime.lock().map_err(|_| "state locked".to_string())?;
  let runtime = guard.as_mut().ok_or_else(|| "core not started".to_string())?;
  f(runtime)
}

#[tauri::command]
fn start(config: UiConfig, app: AppHandle, state: State<AppState>) -> Result<(), String> {
  let path = resolve_ffi_path(&app)?;
  let (config_store, tick_interval) = build_config(&app, config)?;
  let node_config = config_store.to_node_config();
  let mut guard = state.runtime.lock().map_err(|_| "state locked".to_string())?;
  *guard = None;

  let ffi = unsafe { FfiApi::load(&path)? };
  let handle_ptr = unsafe { (ffi.create)() };
  if handle_ptr.is_null() {
    return Err("ffi create failed".to_string());
  }
  let handle = HandlePtr(handle_ptr);
  unsafe {
    (ffi.set_event_callback)(handle.0, core_event_callback as EventCallback, std::ptr::null_mut());
  }

  let ok = unsafe { (ffi.start)(handle.0, &node_config) };
  if !ok {
    let message = unsafe { ffi.error_message().unwrap_or_else(|| "ffi start failed".to_string()) };
    unsafe { (ffi.destroy)(handle.0) };
    return Err(message);
  }

  let tick_stop = Arc::new(AtomicBool::new(false));
  let tick_flag = tick_stop.clone();
  let tick_handle = handle;
  let tick_fn = ffi.tick;
  let tick_thread = thread::spawn(move || {
    let handle = tick_handle;
    while !tick_flag.load(Ordering::Relaxed) {
      unsafe { (tick_fn)(handle.0, now_ms()) };
      thread::sleep(Duration::from_millis(tick_interval));
    }
  });

  *guard = Some(CoreRuntime {
    ffi,
    handle,
    tick_stop,
    tick_thread: Some(tick_thread),
  });

  Ok(())
}

#[tauri::command]
fn stop(state: State<AppState>) -> Result<(), String> {
  let mut guard = state.runtime.lock().map_err(|_| "state locked".to_string())?;
  *guard = None;
  Ok(())
}

#[tauri::command]
fn local_bundle(state: State<AppState>) -> Result<String, String> {
  with_runtime(&state, |runtime| unsafe {
    let ptr = (runtime.ffi.local_bundle_hex)(runtime.handle.0);
    runtime.ffi.take_string(ptr).ok_or_else(|| "bundle unavailable".to_string())
  })
}

#[tauri::command]
fn local_ice(state: State<AppState>) -> Result<String, String> {
  with_runtime(&state, |runtime| unsafe {
    let ptr = (runtime.ffi.local_ice)(runtime.handle.0);
    runtime.ffi.take_string(ptr).ok_or_else(|| "ice unavailable".to_string())
  })
}

#[tauri::command]
fn begin_link(state: State<AppState>) -> Result<String, String> {
  with_runtime(&state, |runtime| unsafe {
    let ptr = (runtime.ffi.begin_link)(runtime.handle.0);
    runtime.ffi.take_string(ptr).ok_or_else(|| "link code unavailable".to_string())
  })
}

#[tauri::command]
fn add_contact_hex(bundle_hex: String, username: Option<String>, state: State<AppState>) -> Result<String, String> {
  let bytes = hex_to_bytes(&bundle_hex)?;
  with_runtime(&state, |runtime| unsafe {
    let ptr = if let Some(name) = username {
      let name_c = FfiApi::to_cstring(&name);
      (runtime.ffi.add_contact_with_username)(runtime.handle.0, bytes.as_ptr(), bytes.len(), name_c.as_ptr())
    } else {
      (runtime.ffi.add_contact)(runtime.handle.0, bytes.as_ptr(), bytes.len())
    };
    runtime.ffi.take_string(ptr).ok_or_else(|| "add contact failed".to_string())
  })
}

#[tauri::command]
fn connect_peer(peer_id: String, address: Option<String>, port: Option<u16>, ice_blob: Option<String>, state: State<AppState>) -> Result<(), String> {
  with_runtime(&state, |runtime| unsafe {
    let peer_id_c = FfiApi::to_cstring(&peer_id);
    let address_c = address.as_deref().map(FfiApi::to_cstring);
    let ice_c = ice_blob.as_deref().map(FfiApi::to_cstring);
    let info = PeerInfo {
      peer_id: peer_id_c.as_ptr(),
      address: address_c.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null()),
      port: port.unwrap_or(0),
      ice_blob: ice_c.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null()),
    };
    let ok = (runtime.ffi.connect_peer)(runtime.handle.0, &info);
    if ok {
      Ok(())
    } else {
      Err(runtime.ffi.error_message().unwrap_or_else(|| "connect failed".to_string()))
    }
  })
}

#[tauri::command]
fn send_text(peer_id: String, message: String, state: State<AppState>) -> Result<(), String> {
  with_runtime(&state, |runtime| unsafe {
    let peer_id_c = FfiApi::to_cstring(&peer_id);
    let ok = (runtime.ffi.send)(
      runtime.handle.0,
      peer_id_c.as_ptr(),
      message.as_bytes().as_ptr(),
      message.as_bytes().len(),
      1,
    );
    if ok {
      Ok(())
    } else {
      Err(runtime.ffi.error_message().unwrap_or_else(|| "send failed".to_string()))
    }
  })
}

#[tauri::command]
fn send_binary(peer_id: String, payload: Vec<u8>, state: State<AppState>) -> Result<(), String> {
  with_runtime(&state, |runtime| unsafe {
    let peer_id_c = FfiApi::to_cstring(&peer_id);
    let ok = (runtime.ffi.send)(
      runtime.handle.0,
      peer_id_c.as_ptr(),
      payload.as_ptr(),
      payload.len(),
      2,
    );
    if ok {
      Ok(())
    } else {
      Err(runtime.ffi.error_message().unwrap_or_else(|| "send failed".to_string()))
    }
  })
}

#[tauri::command]
fn get_history(peer_id: String, cursor: i64, limit: usize, state: State<AppState>) -> Result<serde_json::Value, String> {
  with_runtime(&state, |runtime| unsafe {
    let peer_id_c = FfiApi::to_cstring(&peer_id);
    let ptr = (runtime.ffi.get_history_json)(runtime.handle.0, peer_id_c.as_ptr(), cursor, limit);
    let json = runtime.ffi.take_string(ptr).ok_or_else(|| "history unavailable".to_string())?;
    serde_json::from_str(&json).map_err(|e| e.to_string())
  })
}

#[tauri::command]
fn link_device(code: String, state: State<AppState>) -> Result<(), String> {
  with_runtime(&state, |runtime| unsafe {
    let code_c = FfiApi::to_cstring(&code);
    let ok = (runtime.ffi.link_device)(runtime.handle.0, code_c.as_ptr());
    if ok {
      Ok(())
    } else {
      Err(runtime.ffi.error_message().unwrap_or_else(|| "link failed".to_string()))
    }
  })
}

#[tauri::command]
fn local_username(state: State<AppState>) -> Result<String, String> {
  with_runtime(&state, |runtime| unsafe {
    let ptr = (runtime.ffi.local_username)(runtime.handle.0);
    runtime.ffi.take_string(ptr).ok_or_else(|| "username unavailable".to_string())
  })
}

#[tauri::command]
fn identity_public_key_hex(state: State<AppState>) -> Result<String, String> {
  with_runtime(&state, |runtime| unsafe {
    let ptr = (runtime.ffi.identity_public_key_hex)(runtime.handle.0);
    runtime.ffi.take_string(ptr).ok_or_else(|| "identity key unavailable".to_string())
  })
}

#[tauri::command]
fn sign_identity_hex(message_hex: String, state: State<AppState>) -> Result<String, String> {
  let bytes = hex_to_bytes(&message_hex)?;
  with_runtime(&state, |runtime| unsafe {
    let ptr = (runtime.ffi.sign_identity_hex)(runtime.handle.0, bytes.as_ptr(), bytes.len());
    runtime.ffi.take_string(ptr).ok_or_else(|| "signature unavailable".to_string())
  })
}

#[tauri::command]
fn update_profile(username: Option<String>, password: Option<String>, state: State<AppState>) -> Result<(), String> {
  with_runtime(&state, |runtime| unsafe {
    let name_c = FfiApi::to_cstring(username.as_deref().unwrap_or(""));
    let pass_c = FfiApi::to_cstring(password.as_deref().unwrap_or(""));
    let ok = (runtime.ffi.update_profile)(runtime.handle.0, name_c.as_ptr(), pass_c.as_ptr());
    if ok {
      Ok(())
    } else {
      Err(runtime.ffi.error_message().unwrap_or_else(|| "update profile failed".to_string()))
    }
  })
}

fn main() {
  let (sender, receiver) = mpsc::channel::<CoreEvent>();
  let _ = EVENT_SENDER.set(sender);

  tauri::Builder::default()
    .manage(AppState {
      runtime: Mutex::new(None),
    })
    .setup(move |app| {
      let app_handle = app.handle();
      thread::spawn(move || {
        while let Ok(event) = receiver.recv() {
          let _ = app_handle.emit_all("core-event", event);
        }
      });
      Ok(())
    })
    .invoke_handler(tauri::generate_handler![
      start,
      stop,
      local_bundle,
      local_ice,
      begin_link,
      add_contact_hex,
      connect_peer,
      send_text,
      send_binary,
      get_history,
      link_device,
      local_username,
      identity_public_key_hex,
      sign_identity_hex,
      update_profile
    ])
    .run(tauri::generate_context!())
    .expect("tauri run failed");
}
