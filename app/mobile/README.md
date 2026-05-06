# P2PChat Mobile

React Native client for the P2PChat core bridge.

## Local Checks

Run these from `app/mobile` before shipping a build:

```sh
npm install
npm run typecheck
npm run lint
npm test -- --runInBand
npm audit
```

## Android

Debug builds use the React Native debug keystore:

```sh
npm run android
```

Release builds are minified, shrink resources, and disable cleartext traffic by default:

```sh
npm run android:release
```

Set release signing through environment variables or Gradle properties:

```sh
P2PCHAT_RELEASE_STORE_FILE=/absolute/path/release.keystore
P2PCHAT_RELEASE_STORE_PASSWORD=...
P2PCHAT_RELEASE_KEY_ALIAS=...
P2PCHAT_RELEASE_KEY_PASSWORD=...
```

The native bridge links OpenSSL in CMake. Android release builds require a cross-compiled OpenSSL install for the active Android ABI. Set one of:

```sh
P2PCHAT_ANDROID_OPENSSL_ROOT=/absolute/path/to/android/openssl
```

or:

```sh
./gradlew assembleRelease -Pp2pchatAndroidOpenSslRoot=/absolute/path/to/android/openssl
```

## iOS

Install pods before building in Xcode or with the React Native CLI:

```sh
cd ios
bundle install
bundle exec pod install
cd ..
npm run ios
```

The bridge pod depends on `OpenSSL-Universal`.

## Production Notes

- Keep directory-service URLs in app configuration, not hard-coded into release binaries.
- Use separate app identifiers, signing profiles, and storage directories for staging and production builds.
- Re-run the local checks after any bridge, schema, or native dependency change.
