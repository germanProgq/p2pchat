# p2pchat

A peer-to-peer encrypted messaging project. The core is C++17: identity, end-to-end crypto, session handling, local storage, and transport. On top of that core there is a C FFI layer that a Tauri desktop app (Rust backend, React UI) and a React Native bridge both call into, so the same core runs on desktop and mobile.

This is a work in progress. It aims to run without paid services.

## Components

- `core/identity`: identity keys and key storage, backed by SQLite and OpenSSL
- `core/crypto`: cryptographic primitives, X3DH key agreement, and a Double Ratchet
- `core/session`: session setup, handshake, and message exchange state
- `core/storage`: encrypted local message and session storage (SQLite)
- `core/transport`: transport abstraction, including a loopback transport for headless tests
- `core/security`: security helpers
- `app/bridge`: C++ bridge plus a React Native module (iOS and Android) that speaks a JSON event protocol
- `desktop/ffi`: `p2pchat_ffi`, a C FFI shared library that wraps the core for in-process use
- `desktop/tauri`: the Tauri desktop app (Rust backend and React/Vite UI) that loads the FFI library
- `tools/directory`: a small Node directory server used to help peers find each other
- `tests`: CTest unit and integration suites per module, plus an end-to-end flow test

## Build the core and tests

Requires CMake 3.20+, a C++17 compiler, OpenSSL, and SQLite3. On macOS the build script finds OpenSSL from Homebrew.

```bash
cmake -S . -B build
cmake --build build
```

## Run the tests

```bash
ctest --test-dir build --output-on-failure
```

The suites cover identity, crypto, storage, transport, session, core, the bridge, security, the desktop FFI, and the end-to-end flow.

## Desktop app

`scripts/run_desktop.sh` builds the core, builds the FFI library, brings up the directory server with Docker Compose, and launches the Tauri app. It needs CMake and Docker available.

```bash
./scripts/run_desktop.sh
```

The desktop app stores data in a per-user application directory and targets macOS, Windows, and Linux.

## Documentation

`docs/e2e_flow.md` describes the two-device session and message flow. `docs/desktop_app.md` covers desktop packaging, runtime choices, and data paths.

## Security note

This project implements its own session and messaging layer on top of standard primitives. It has not been independently audited. Treat it as experimental and do not rely on it for high-risk communication.
