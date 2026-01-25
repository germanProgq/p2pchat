// Desktop app entry point. Spec: docs/desktop_app.md.
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "bridge/BridgeJson.h"
#include "core/Core.h"
#include "crypto/X3DH.h"
#include "identity/IdentityStore.h"
#include "session/SessionManager.h"
#include "transport/ITransport.h"
#include "transport/LoopbackTransport.h"

namespace {

struct CliOptions {
  bool help = false;
  bool smoke = false;
  std::string data_dir;
  std::string identity_path;
  std::string storage_path;
  std::string schema_path;
  std::string username;
  std::string password;
  std::string transport = "quic";
  std::string bind_address = "0.0.0.0";
  uint16_t bind_port = 0;
  std::string service_name = "p2pchat";
  std::optional<std::array<uint8_t, 32>> master_key;
  int tick_interval_ms = 50;
};

std::mutex g_io_mutex;

int64_t nowMs() {
  using namespace std::chrono;
  return static_cast<int64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

void emitLine(const std::string& line, bool is_error = false) {
  std::lock_guard<std::mutex> lock(g_io_mutex);
  if (is_error) {
    std::cerr << line << std::endl;
  } else {
    std::cout << line << std::endl;
  }
}

void emitEvent(const std::string& name, const std::string& payload_json) {
  std::lock_guard<std::mutex> lock(g_io_mutex);
  std::cout << "{\"event\":\"" << name << "\",\"payload\":" << payload_json << "}" << std::endl;
}

std::string ltrim(const std::string& text) {
  size_t idx = 0;
  while (idx < text.size() && std::isspace(static_cast<unsigned char>(text[idx]))) {
    idx++;
  }
  return text.substr(idx);
}

bool parsePort(const std::string& text, uint16_t& port) {
  if (text.empty()) {
    return false;
  }
  uint32_t value = 0;
  for (char c : text) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      return false;
    }
    value = value * 10 + static_cast<uint32_t>(c - '0');
    if (value > 65535) {
      return false;
    }
  }
  port = static_cast<uint16_t>(value);
  return true;
}

std::string bytesToHex(const std::vector<uint8_t>& bytes) {
  static const char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    out.push_back(kHex[b >> 4]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

bool hexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
  if (hex.size() % 2 != 0) {
    return false;
  }
  out.clear();
  out.reserve(hex.size() / 2);
  auto nibble = [](char c, uint8_t& v) {
    if (c >= '0' && c <= '9') {
      v = static_cast<uint8_t>(c - '0');
      return true;
    }
    if (c >= 'a' && c <= 'f') {
      v = static_cast<uint8_t>(10 + (c - 'a'));
      return true;
    }
    if (c >= 'A' && c <= 'F') {
      v = static_cast<uint8_t>(10 + (c - 'A'));
      return true;
    }
    return false;
  };
  for (size_t i = 0; i < hex.size(); i += 2) {
    uint8_t hi = 0;
    uint8_t lo = 0;
    if (!nibble(hex[i], hi) || !nibble(hex[i + 1], lo)) {
      return false;
    }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

bool readFileBytes(const std::filesystem::path& path, std::vector<uint8_t>& out) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    return false;
  }
  in.seekg(0, std::ios::end);
  std::streamsize size = in.tellg();
  if (size < 0) {
    return false;
  }
  in.seekg(0, std::ios::beg);
  out.resize(static_cast<size_t>(size));
  if (size > 0 && !in.read(reinterpret_cast<char*>(out.data()), size)) {
    return false;
  }
  return true;
}

bool writeFileBytes(const std::filesystem::path& path, const std::vector<uint8_t>& data) {
  if (!path.parent_path().empty()) {
    std::filesystem::create_directories(path.parent_path());
  }
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) {
    return false;
  }
  if (!data.empty()) {
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
  }
  return static_cast<bool>(out);
}

std::filesystem::path defaultDataDir() {
#ifdef _WIN32
  const char* appdata = std::getenv("APPDATA");
  if (appdata && *appdata) {
    return std::filesystem::path(appdata) / "p2pchat";
  }
#elif defined(__APPLE__)
  const char* home = std::getenv("HOME");
  if (home && *home) {
    return std::filesystem::path(home) / "Library" / "Application Support" / "p2pchat";
  }
#else
  const char* xdg = std::getenv("XDG_DATA_HOME");
  if (xdg && *xdg) {
    return std::filesystem::path(xdg) / "p2pchat";
  }
  const char* home = std::getenv("HOME");
  if (home && *home) {
    return std::filesystem::path(home) / ".local" / "share" / "p2pchat";
  }
#endif
  return std::filesystem::current_path() / "p2pchat_data";
}

std::filesystem::path executableDir(const char* argv0) {
  if (!argv0 || !*argv0) {
    return std::filesystem::current_path();
  }
  std::filesystem::path path = std::filesystem::absolute(argv0);
  if (path.has_parent_path()) {
    return path.parent_path();
  }
  return std::filesystem::current_path();
}

std::filesystem::path resolveSchemaPath(const std::string& cli_path, const std::filesystem::path& exe_dir) {
  if (!cli_path.empty()) {
    return std::filesystem::path(cli_path);
  }
  const char* env = std::getenv("P2PCHAT_SCHEMA_PATH");
  if (env && *env) {
    return std::filesystem::path(env);
  }
#ifdef P2PCHAT_SOURCE_DIR
  std::filesystem::path dev = std::filesystem::path(P2PCHAT_SOURCE_DIR) / "core" / "storage" / "schema.sql";
  if (std::filesystem::exists(dev)) {
    return dev;
  }
#endif
  std::filesystem::path installed = exe_dir / ".." / "share" / "p2pchat" / "schema.sql";
  if (std::filesystem::exists(installed)) {
    return installed;
  }
  std::filesystem::path local = exe_dir / "schema.sql";
  if (std::filesystem::exists(local)) {
    return local;
  }
  return installed;
}

bridge::ContentType toBridgeContentType(uint8_t value) {
  if (value == static_cast<uint8_t>(session::ContentType::Text)) {
    return bridge::ContentType::Text;
  }
  return bridge::ContentType::Binary;
}

bridge::IncomingMessage toBridgeMessage(const session::IncomingMessage& msg) {
  bridge::IncomingMessage out;
  out.chat_id = msg.chat_id;
  out.msg_id = msg.msg_id;
  out.sender_device = msg.sender_device;
  out.ts_ms = msg.ts_ms;
  out.content_type = toBridgeContentType(msg.content_type);
  out.body = msg.body;
  return out;
}

bridge::HistoryMessage toBridgeHistory(const session::HistoryMessage& msg) {
  bridge::HistoryMessage out;
  out.chat_id = msg.chat_id;
  out.msg_id = msg.msg_id;
  out.sender_device = msg.sender_device;
  out.ts_ms = msg.ts_ms;
  out.content_type = toBridgeContentType(msg.content_type);
  out.body = msg.body;
  out.delivered = msg.delivered;
  out.acked = msg.acked;
  out.index = msg.index;
  return out;
}

bridge::ConnectionEvent toBridgeConnection(const transport::PeerId& peer, transport::ConnectionState state) {
  bridge::ConnectionEvent event;
  event.peer_id = peer;
  switch (state) {
    case transport::ConnectionState::Disconnected:
      event.state = bridge::ConnectionState::Disconnected;
      break;
    case transport::ConnectionState::Connecting:
      event.state = bridge::ConnectionState::Connecting;
      break;
    case transport::ConnectionState::Connected:
      event.state = bridge::ConnectionState::Connected;
      break;
  }
  return event;
}

bridge::PeerStatusEvent toBridgePeerStatus(const transport::PeerId& peer, core::PeerStatus status) {
  bridge::PeerStatusEvent event;
  event.peer_id = peer;
  switch (status) {
    case core::PeerStatus::Pending:
      event.status = bridge::PeerStatus::Pending;
      break;
    case core::PeerStatus::Ready:
      event.status = bridge::PeerStatus::Ready;
      break;
    case core::PeerStatus::Failed:
      event.status = bridge::PeerStatus::Failed;
      break;
  }
  return event;
}

bridge::ErrorEvent toBridgeError(const transport::PeerId& peer, const std::string& message) {
  bridge::ErrorEvent event;
  event.peer_id = peer;
  event.message = message;
  return event;
}

class TickLoop {
 public:
  TickLoop(core::Core& core, std::mutex& mutex, int interval_ms)
      : core_(core), mutex_(mutex), interval_ms_(interval_ms) {}

  void start() {
    running_.store(true);
    thread_ = std::thread([this]() { run(); });
  }

  void stop() {
    running_.store(false);
    if (thread_.joinable()) {
      thread_.join();
    }
  }

 private:
  void run() {
    while (running_.load()) {
      {
        std::lock_guard<std::mutex> lock(mutex_);
        core_.tick(nowMs());
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms_));
    }
  }

  core::Core& core_;
  std::mutex& mutex_;
  int interval_ms_ = 50;
  std::atomic<bool> running_{false};
  std::thread thread_;
};

class DesktopRuntime {
 public:
  DesktopRuntime() = default;

  void start(const core::NodeConfig& config, int tick_interval_ms) {
    tick_loop_ = std::make_unique<TickLoop>(core_, core_mutex_, tick_interval_ms);
    bindEvents();
    {
      std::lock_guard<std::mutex> lock(core_mutex_);
      core_.start(config);
    }
    tick_loop_->start();
  }

  void stop() {
    if (tick_loop_) {
      tick_loop_->stop();
    }
    std::lock_guard<std::mutex> lock(core_mutex_);
    core_.stop();
  }

  std::string localBundleHex() {
    std::lock_guard<std::mutex> lock(core_mutex_);
    auto bundle = core_.localPreKeyBundle();
    return bytesToHex(crypto::serializePreKeyBundle(bundle));
  }

  std::vector<uint8_t> localBundleBytes() {
    std::lock_guard<std::mutex> lock(core_mutex_);
    auto bundle = core_.localPreKeyBundle();
    return crypto::serializePreKeyBundle(bundle);
  }

  std::string localIce() {
    std::lock_guard<std::mutex> lock(core_mutex_);
    return core_.localIceDescription();
  }

  std::string linkCode() {
    std::lock_guard<std::mutex> lock(core_mutex_);
    return core_.beginLink();
  }

  std::string addContactBytes(const std::vector<uint8_t>& bytes) {
    crypto::PreKeyBundle bundle = crypto::parsePreKeyBundle(bytes);
    std::lock_guard<std::mutex> lock(core_mutex_);
    return core_.addContact(bundle);
  }

  void connectPeer(const transport::PeerInfo& info) {
    std::lock_guard<std::mutex> lock(core_mutex_);
    core_.connectPeer(info);
  }

  void sendText(const std::string& peer_id, const std::string& text) {
    std::vector<uint8_t> bytes(text.begin(), text.end());
    std::lock_guard<std::mutex> lock(core_mutex_);
    core_.send(peer_id, bytes, static_cast<uint8_t>(session::ContentType::Text));
  }

  void sendBytes(const std::string& peer_id, const std::vector<uint8_t>& bytes) {
    std::lock_guard<std::mutex> lock(core_mutex_);
    core_.send(peer_id, bytes, static_cast<uint8_t>(session::ContentType::Binary));
  }

  std::vector<bridge::HistoryMessage> history(const std::string& peer_id, int64_t start, size_t limit) {
    std::lock_guard<std::mutex> lock(core_mutex_);
    auto entries = core_.getHistory(peer_id, start, limit);
    std::vector<bridge::HistoryMessage> out;
    out.reserve(entries.size());
    for (const auto& entry : entries) {
      out.push_back(toBridgeHistory(entry));
    }
    return out;
  }

  void linkDevice(const std::string& code) {
    std::lock_guard<std::mutex> lock(core_mutex_);
    core_.linkDevice(code);
  }

 private:
  void bindEvents() {
    core_.onMessage = [](const session::IncomingMessage& msg) {
      emitEvent("onMessage", bridge::toJsonPayload(toBridgeMessage(msg)));
    };
    core_.onConnectionChange = [](const transport::PeerId& peer, transport::ConnectionState state) {
      emitEvent("onConnectionChange", bridge::toJsonPayload(toBridgeConnection(peer, state)));
    };
    core_.onPeerStatus = [](const transport::PeerId& peer, core::PeerStatus status) {
      emitEvent("onPeerStatus", bridge::toJsonPayload(toBridgePeerStatus(peer, status)));
    };
    core_.onError = [](const transport::PeerId& peer, const std::string& message) {
      emitEvent("onError", bridge::toJsonPayload(toBridgeError(peer, message)));
    };
  }

  core::Core core_;
  std::mutex core_mutex_;
  std::unique_ptr<TickLoop> tick_loop_;
};

void printUsage() {
  emitLine("p2pchat_desktop [--data-dir DIR] [--identity PATH] [--storage PATH] [--schema PATH]", false);
  emitLine("                [--username NAME] [--password PASS] [--transport quic|webrtc|loopback] [--bind ADDR] [--port PORT]", false);
  emitLine("                [--master-key-hex HEX32] [--service-name NAME] [--tick-ms MS] [--smoke]", false);
  emitLine("", false);
  emitLine("Commands:", false);
  emitLine("  help", false);
  emitLine("  bundle", false);
  emitLine("  bundle-out <path>", false);
  emitLine("  add <bundle-hex>", false);
  emitLine("  add-file <path>", false);
  emitLine("  ice", false);
  emitLine("  connect <peer-id> <address> <port>", false);
  emitLine("  connect-ice <peer-id> <ice-blob>", false);
  emitLine("  send <peer-id> <message>", false);
  emitLine("  send-hex <peer-id> <hex>", false);
  emitLine("  history <peer-id> [start] [limit]", false);
  emitLine("  link-code", false);
  emitLine("  link <code>", false);
  emitLine("  quit", false);
}

bool parseArgs(int argc, char** argv, CliOptions& options, std::string& error) {
  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];
    if (arg == "--help" || arg == "-h") {
      options.help = true;
      return true;
    }
    if (arg == "--smoke") {
      options.smoke = true;
      continue;
    }
    if (arg == "--data-dir" && i + 1 < argc) {
      options.data_dir = argv[++i];
      continue;
    }
    if (arg == "--identity" && i + 1 < argc) {
      options.identity_path = argv[++i];
      continue;
    }
    if (arg == "--storage" && i + 1 < argc) {
      options.storage_path = argv[++i];
      continue;
    }
    if (arg == "--schema" && i + 1 < argc) {
      options.schema_path = argv[++i];
      continue;
    }
    if (arg == "--username" && i + 1 < argc) {
      options.username = argv[++i];
      continue;
    }
    if (arg == "--password" && i + 1 < argc) {
      options.password = argv[++i];
      continue;
    }
    if (arg == "--transport" && i + 1 < argc) {
      std::string value = argv[++i];
      std::string lower = value;
      for (auto& c : lower) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      if (lower != "quic" && lower != "webrtc" && lower != "loopback") {
        error = "transport must be quic, webrtc, or loopback";
        return false;
      }
      options.transport = value;
      continue;
    }
    if (arg == "--bind" && i + 1 < argc) {
      options.bind_address = argv[++i];
      continue;
    }
    if (arg == "--port" && i + 1 < argc) {
      uint16_t port = 0;
      if (!parsePort(argv[i + 1], port)) {
        error = "invalid port";
        return false;
      }
      options.bind_port = port;
      ++i;
      continue;
    }
    if (arg == "--service-name" && i + 1 < argc) {
      options.service_name = argv[++i];
      continue;
    }
    if (arg == "--tick-ms" && i + 1 < argc) {
      int value = 0;
      try {
        value = std::stoi(argv[++i]);
      } catch (const std::exception&) {
        error = "invalid tick interval";
        return false;
      }
      if (value <= 0) {
        error = "tick interval must be positive";
        return false;
      }
      options.tick_interval_ms = value;
      continue;
    }
    if (arg == "--master-key-hex" && i + 1 < argc) {
      std::vector<uint8_t> bytes;
      if (!hexToBytes(argv[i + 1], bytes) || bytes.size() != 32) {
        error = "master key hex must be 32 bytes";
        return false;
      }
      std::array<uint8_t, 32> key{};
      std::copy(bytes.begin(), bytes.end(), key.begin());
      options.master_key = key;
      ++i;
      continue;
    }
    error = "unknown argument: " + arg;
    return false;
  }
  return true;
}

core::TransportKind parseTransportKind(const std::string& value) {
  std::string lower = value;
  for (auto& c : lower) {
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  }
  if (lower == "loopback") {
    return core::TransportKind::Loopback;
  }
  if (lower == "webrtc") {
    return core::TransportKind::WebRtc;
  }
  return core::TransportKind::Quic;
}

core::NodeConfig buildConfig(const CliOptions& options, const std::filesystem::path& exe_dir) {
  std::filesystem::path data_dir = options.data_dir.empty() ? defaultDataDir() : std::filesystem::path(options.data_dir);
  std::filesystem::create_directories(data_dir);
  core::NodeConfig config;
  config.identity_path = options.identity_path.empty() ? (data_dir / "identity.bin").string() : options.identity_path;
  config.storage_path = options.storage_path.empty() ? (data_dir / "store.db").string() : options.storage_path;
  config.schema_path = resolveSchemaPath(options.schema_path, exe_dir).string();
  if (!options.username.empty()) {
    config.username = options.username;
  } else if (const char* env_user = std::getenv("P2PCHAT_USERNAME")) {
    config.username = env_user;
  }
  if (!options.password.empty()) {
    config.password = options.password;
  } else if (const char* env_pass = std::getenv("P2PCHAT_PASSWORD")) {
    config.password = env_pass;
  }
  if (options.master_key.has_value()) {
    config.master_key = std::make_shared<identity::InMemoryKeyStore>(*options.master_key);
  } else {
    config.master_key = std::make_shared<identity::OsKeyStore>(options.service_name);
  }
  config.transport_kind = parseTransportKind(options.transport);
  config.quic.bind_address = options.bind_address;
  config.quic.bind_port = options.bind_port;
  config.webrtc.bind_address = options.bind_address;
  config.webrtc.bind_port = options.bind_port;
  return config;
}

std::array<uint8_t, 32> fixedMasterKey() {
  std::array<uint8_t, 32> key{};
  for (size_t i = 0; i < key.size(); ++i) {
    key[i] = static_cast<uint8_t>(0x42 + i);
  }
  return key;
}

bool runSmoke(const CliOptions& options, const std::filesystem::path& exe_dir) {
  transport::LoopbackNetwork network;

  auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
  std::filesystem::path dirA = std::filesystem::temp_directory_path() / ("p2pchat_desktop_smoke_a_" + std::to_string(now));
  std::filesystem::path dirB = std::filesystem::temp_directory_path() / ("p2pchat_desktop_smoke_b_" + std::to_string(now));
  std::filesystem::create_directories(dirA);
  std::filesystem::create_directories(dirB);

  core::NodeConfig configA = buildConfig(options, exe_dir);
  configA.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedMasterKey());
  configA.identity_path = (dirA / "identity.bin").string();
  configA.storage_path = (dirA / "store.db").string();
  configA.username = "smoke-a";
  configA.password = "password123";
  configA.transport_kind = core::TransportKind::Loopback;
  configA.loopback_network = &network;
  configA.handshake_base_delay_ms = 5;
  configA.handshake_max_delay_ms = 20;
  configA.handshake_max_attempts = 3;

  core::NodeConfig configB = configA;
  configB.identity_path = (dirB / "identity.bin").string();
  configB.storage_path = (dirB / "store.db").string();
  configB.master_key = std::make_shared<identity::InMemoryKeyStore>(fixedMasterKey());
  configB.username = "smoke-b";
  configB.password = "password123";

  core::Core coreA;
  core::Core coreB;
  if (!std::filesystem::exists(configA.schema_path)) {
    emitLine("smoke: schema not found at " + configA.schema_path, true);
    return false;
  }
  coreA.start(configA);
  coreB.start(configB);

  bool received = false;
  std::string payload;
  coreB.onMessage = [&](const session::IncomingMessage& msg) {
    bridge::IncomingMessage converted = toBridgeMessage(msg);
    payload = bridge::toJsonPayload(converted);
    received = true;
  };

  std::string peer_id = coreA.addContact(coreB.localPreKeyBundle());
  transport::PeerInfo peer;
  peer.id = peer_id;
  coreA.connectPeer(peer);

  coreA.send(peer_id, std::vector<uint8_t>{'s', 'm', 'o', 'k', 'e'});
  int64_t start = nowMs();
  for (int i = 0; i < 20; ++i) {
    int64_t t = start + i * 10;
    coreA.tick(t);
    coreB.tick(t);
    if (received) {
      break;
    }
  }

  coreA.stop();
  coreB.stop();

  if (!received) {
    emitLine("smoke: message not received", true);
    return false;
  }
  if (payload.find("\"chatId\"") == std::string::npos) {
    emitLine("smoke: bridge payload missing chatId", true);
    return false;
  }
  return true;
}

void repl(DesktopRuntime& runtime) {
  emitLine("p2pchat desktop shell ready. Type 'help' for commands.");
  std::string line;
  while (true) {
    {
      std::lock_guard<std::mutex> lock(g_io_mutex);
      std::cout << "> " << std::flush;
    }
    if (!std::getline(std::cin, line)) {
      break;
    }
    line = ltrim(line);
    if (line.empty()) {
      continue;
    }
    std::istringstream iss(line);
    std::string cmd;
    iss >> cmd;
    if (cmd == "help") {
      printUsage();
      continue;
    }
    if (cmd == "quit" || cmd == "exit") {
      break;
    }
    if (cmd == "bundle") {
      emitLine(runtime.localBundleHex());
      continue;
    }
    if (cmd == "bundle-out") {
      std::string path;
      std::getline(iss, path);
      path = ltrim(path);
      if (path.empty()) {
        emitLine("bundle-out requires a path", true);
        continue;
      }
      auto bytes = runtime.localBundleBytes();
      if (!writeFileBytes(path, bytes)) {
        emitLine("failed to write bundle", true);
        continue;
      }
      emitLine("bundle saved to " + path);
      continue;
    }
    if (cmd == "add") {
      std::string hex;
      iss >> hex;
      if (hex.empty()) {
        emitLine("add requires bundle hex", true);
        continue;
      }
      std::vector<uint8_t> bytes;
      if (!hexToBytes(hex, bytes)) {
        emitLine("invalid bundle hex", true);
        continue;
      }
      try {
        std::string peer_id = runtime.addContactBytes(bytes);
        emitLine("peer-id " + peer_id);
      } catch (const std::exception& ex) {
        emitLine(std::string("add failed: ") + ex.what(), true);
      }
      continue;
    }
    if (cmd == "add-file") {
      std::string path;
      std::getline(iss, path);
      path = ltrim(path);
      if (path.empty()) {
        emitLine("add-file requires a path", true);
        continue;
      }
      std::vector<uint8_t> bytes;
      if (!readFileBytes(path, bytes)) {
        emitLine("failed to read bundle file", true);
        continue;
      }
      try {
        std::string peer_id = runtime.addContactBytes(bytes);
        emitLine("peer-id " + peer_id);
      } catch (const std::exception& ex) {
        emitLine(std::string("add failed: ") + ex.what(), true);
      }
      continue;
    }
    if (cmd == "ice") {
      std::string ice = runtime.localIce();
      if (ice.empty()) {
        emitLine("ice unavailable for current transport", true);
      } else {
        emitLine(ice);
      }
      continue;
    }
    if (cmd == "connect") {
      std::string peer_id;
      std::string addr;
      std::string port_str;
      iss >> peer_id >> addr >> port_str;
      if (peer_id.empty() || addr.empty() || port_str.empty()) {
        emitLine("connect requires peer-id, address, and port", true);
        continue;
      }
      uint16_t port = 0;
      if (!parsePort(port_str, port)) {
        emitLine("invalid port", true);
        continue;
      }
      transport::PeerInfo peer;
      peer.id = peer_id;
      peer.address = addr;
      peer.port = port;
      runtime.connectPeer(peer);
      emitLine("connect requested for " + peer_id);
      continue;
    }
    if (cmd == "connect-ice") {
      std::string peer_id;
      iss >> peer_id;
      std::string ice;
      std::getline(iss, ice);
      ice = ltrim(ice);
      if (peer_id.empty() || ice.empty()) {
        emitLine("connect-ice requires peer-id and ice blob", true);
        continue;
      }
      transport::PeerInfo peer;
      peer.id = peer_id;
      peer.ice_blob = ice;
      runtime.connectPeer(peer);
      emitLine("connect-ice requested for " + peer_id);
      continue;
    }
    if (cmd == "send") {
      std::string peer_id;
      iss >> peer_id;
      std::string msg;
      std::getline(iss, msg);
      msg = ltrim(msg);
      if (peer_id.empty() || msg.empty()) {
        emitLine("send requires peer-id and message", true);
        continue;
      }
      try {
        runtime.sendText(peer_id, msg);
      } catch (const std::exception& ex) {
        emitLine(std::string("send failed: ") + ex.what(), true);
      }
      continue;
    }
    if (cmd == "send-hex") {
      std::string peer_id;
      std::string hex;
      iss >> peer_id >> hex;
      if (peer_id.empty() || hex.empty()) {
        emitLine("send-hex requires peer-id and hex payload", true);
        continue;
      }
      std::vector<uint8_t> bytes;
      if (!hexToBytes(hex, bytes)) {
        emitLine("invalid hex", true);
        continue;
      }
      try {
        runtime.sendBytes(peer_id, bytes);
      } catch (const std::exception& ex) {
        emitLine(std::string("send failed: ") + ex.what(), true);
      }
      continue;
    }
    if (cmd == "history") {
      std::string peer_id;
      std::string start_str;
      std::string limit_str;
      iss >> peer_id >> start_str >> limit_str;
      if (peer_id.empty()) {
        emitLine("history requires peer-id", true);
        continue;
      }
      int64_t start = 1;
      size_t limit = 50;
      try {
        if (!start_str.empty()) {
          start = std::stoll(start_str);
        }
        if (!limit_str.empty()) {
          limit = static_cast<size_t>(std::stoul(limit_str));
        }
      } catch (const std::exception&) {
        emitLine("history arguments must be numbers", true);
        continue;
      }
      try {
        auto history = runtime.history(peer_id, start, limit);
        for (const auto& entry : history) {
          emitEvent("history", bridge::toJsonPayload(entry));
        }
      } catch (const std::exception& ex) {
        emitLine(std::string("history failed: ") + ex.what(), true);
      }
      continue;
    }
    if (cmd == "link-code") {
      emitLine(runtime.linkCode());
      continue;
    }
    if (cmd == "link") {
      std::string code;
      iss >> code;
      if (code.empty()) {
        emitLine("link requires a code", true);
        continue;
      }
      try {
        runtime.linkDevice(code);
        emitLine("link requested");
      } catch (const std::exception& ex) {
        emitLine(std::string("link failed: ") + ex.what(), true);
      }
      continue;
    }
    emitLine("unknown command", true);
  }
}

}

int main(int argc, char** argv) {
  CliOptions options;
  std::string error;
  if (!parseArgs(argc, argv, options, error)) {
    emitLine(error, true);
    printUsage();
    return 1;
  }
  if (options.help) {
    printUsage();
    return 0;
  }

  std::filesystem::path exe_dir = executableDir(argv[0]);
  if (options.smoke) {
    return runSmoke(options, exe_dir) ? 0 : 1;
  }

  core::NodeConfig config = buildConfig(options, exe_dir);
  if (!std::filesystem::exists(config.schema_path)) {
    emitLine("schema not found at " + config.schema_path, true);
    return 1;
  }
  if (config.username.empty() || config.password.empty()) {
    emitLine("username/password required (use --username/--password or P2PCHAT_USERNAME/P2PCHAT_PASSWORD)", true);
    return 1;
  }

  DesktopRuntime runtime;
  try {
    runtime.start(config, options.tick_interval_ms);
  } catch (const std::exception& ex) {
    emitLine(std::string("start failed: ") + ex.what(), true);
    return 1;
  }

  repl(runtime);
  runtime.stop();
  return 0;
}
