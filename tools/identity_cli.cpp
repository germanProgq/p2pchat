// Identity CLI for provisioning and validating identity store. Spec: core/identity/README.md.
#include "identity/IdentityStore.h"

#include <array>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/rand.h>

namespace {

std::string defaultStorePath() {
#if defined(_WIN32)
  const char* base = std::getenv("APPDATA");
  std::filesystem::path root = base ? base : ".";
  std::filesystem::path dir = root / "p2pchat";
#else
  const char* base = std::getenv("HOME");
  std::filesystem::path dir = base ? std::filesystem::path(base) / ".p2pchat" : ".";
#endif
  std::filesystem::create_directories(dir);
  return (dir / "identity.store").string();
}

std::array<uint8_t, 32> randomKey() {
  std::array<uint8_t, 32> key{};
  if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
    throw std::runtime_error("RAND_bytes failed");
  }
  return key;
}

void printUsage() {
  std::cout << "identity_cli <command> [--store PATH]\n";
  std::cout << "commands:\n";
  std::cout << "  init        Create a new identity store\n";
  std::cout << "  public-key  Print the active identity public key\n";
  std::cout << "  rotate      Rotate the identity key\n";
  std::cout << "  self-test   Generate, reload, and verify in a temp store\n";
}

}  // namespace

int main(int argc, char** argv) {
  try {
    if (argc < 2) {
      printUsage();
      return 1;
    }
    std::string command;
    std::string store_path;
    for (int i = 1; i < argc; ++i) {
      std::string arg = argv[i];
      if (arg == "--store") {
        if (i + 1 >= argc) {
          throw std::runtime_error("--store requires a path");
        }
        store_path = argv[++i];
      } else if (arg == "--help" || arg == "-h") {
        printUsage();
        return 0;
      } else if (command.empty()) {
        command = arg;
      } else {
        throw std::runtime_error("unexpected argument: " + arg);
      }
    }

    if (command == "self-test") {
      std::filesystem::path dir = std::filesystem::temp_directory_path() /
                                  ("p2pchat_identity_selftest_" + std::to_string(std::time(nullptr)));
      std::filesystem::create_directories(dir);
      std::filesystem::path path = dir / "identity.store";
      auto key_store = std::make_shared<identity::InMemoryKeyStore>(randomKey());
      identity::IdentityStore store({path.string(), key_store});
      identity::IdentityRecord created = store.createNew();
      identity::IdentityRecord loaded = store.load();
      if (created.active.public_key != loaded.active.public_key) {
        throw std::runtime_error("self-test failed: public key mismatch");
      }
      std::cout << "self-test ok" << std::endl;
      std::filesystem::remove(path);
      std::filesystem::remove(dir);
      return 0;
    }

    if (store_path.empty()) {
      store_path = defaultStorePath();
    }

    auto key_store = std::make_shared<identity::OsKeyStore>("com.p2pchat.identity.masterkey");
    identity::IdentityStore store({store_path, key_store});

    if (command == "init") {
      identity::IdentityRecord record = store.createNew();
      std::cout << identity::IdentityStore::toHex(record.active.public_key) << std::endl;
      std::cout << identity::IdentityStore::toHex(identity::IdentityStore::userIdFromPublicKey(record.active.public_key))
                << std::endl;
      return 0;
    }

    if (command == "public-key") {
      identity::IdentityRecord record = store.load();
      std::cout << identity::IdentityStore::toHex(record.active.public_key) << std::endl;
      return 0;
    }

    if (command == "rotate") {
      identity::IdentityRecord record = store.rotateIdentity();
      std::cout << identity::IdentityStore::toHex(record.active.public_key) << std::endl;
      return 0;
    }

    throw std::runtime_error("unknown command: " + command);
  } catch (const std::exception& ex) {
    std::cerr << "error: " << ex.what() << std::endl;
    return 1;
  }
}
