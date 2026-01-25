// React Native config for p2pchat bridge module. Spec: app/bridge/BridgeSpec.md.
module.exports = {
  dependency: {
    platforms: {
      android: {
        sourceDir: './android',
        packageImportPath: 'import com.p2pchat.bridge.BridgePackage;',
        packageInstance: 'new BridgePackage()'
      },
      ios: {
        podspecPath: './p2pchat-bridge.podspec'
      }
    }
  }
};
