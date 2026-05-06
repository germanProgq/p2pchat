Desktop App Packaging (Phase 8 SSOT)

Scope
- Provide a native desktop UI that runs the core in-process and ships for macOS, Windows, and Linux without paid services.
- Desktop UI must include chat list, chat view, composer, settings, connection status, and device link flows described in app.txt.

Runtime Choice
- Tauri desktop app (Rust backend + WebView) with a React UI.
- Core is integrated via an in-process C FFI library (p2pchat_ffi) that wraps core and emits BridgeJson payloads.
- No external paid services or runtime subscriptions.

Bridge Integration
- FFI emits bridge-compatible event payloads (onMessage, onConnectionChange, onPeerStatus, onError) using BridgeJson.
- Tauri backend forwards events to the UI as {"event":"onMessage","payload":{...}} payloads matching BridgeSpec.md.
- UI commands map to bridge-facing actions: start, addContact, send, getHistory, linkDevice, connectPeer, local bundle, and ICE description.

Storage and Paths
- Default data directory:
  - macOS: ~/Library/Application Support/p2pchat
  - Windows: %APPDATA%\p2pchat
  - Linux: $XDG_DATA_HOME/p2pchat or ~/.local/share/p2pchat
- Default schema path resolution order:
  1) CLI --schema
  2) P2PCHAT_SOURCE_DIR/core/storage/schema.sql (dev)
  3) Installed share/p2pchat/schema.sql next to the binary

Packaging
- Tauri bundles the UI and includes the p2pchat_ffi library and schema.sql asset.
- CMake builds p2pchat_ffi for desktop targets; Tauri loads it in-process.
- From desktop/tauri, `npm run build:debug` builds a local debug bundle and `npm run build` builds the release bundle.
- The Tauri build runs scripts/prepare_tauri_resources.sh to compile the FFI library, copy resources, and build the browser UI.

Browser Build
- The React UI also runs in a normal browser through the browser fallback bridge in ui/src/api.ts.
- Browser mode stores identity, contacts, and message history in localStorage and exchanges same-origin test messages through BroadcastChannel.
- Browser mode is suitable for hosted demos and web smoke testing; native P2P transport still requires the desktop/mobile bridge.

Manual Test
1) Build and launch two desktop instances with distinct data directories and ports.
2) On each instance, copy the local prekey bundle from Settings.
3) On each instance, add the other bundle and connect via address/port or ICE.
4) Send a message from A to B and confirm receipt in the UI and onMessage event payloads.

Automated Test
- Desktop FFI loopback test validates handshake, send, and history JSON.
