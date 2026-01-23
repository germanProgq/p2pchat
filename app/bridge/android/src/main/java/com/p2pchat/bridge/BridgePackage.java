// TurboModule package registration for Bridge. Spec: app/bridge/BridgeSpec.md.
package com.p2pchat.bridge;

import androidx.annotation.Nullable;

import com.facebook.react.ReactPackage;
import com.facebook.react.TurboReactPackage;
import com.facebook.react.bridge.NativeModule;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.module.model.ReactModuleInfo;
import com.facebook.react.module.model.ReactModuleInfoProvider;

import java.util.HashMap;
import java.util.Map;

public final class BridgePackage extends TurboReactPackage implements ReactPackage {
  @Override
  public @Nullable NativeModule getModule(String name, ReactApplicationContext context) {
    if (BridgeModule.NAME.equals(name)) {
      return new BridgeModule(context);
    }
    return null;
  }

  @Override
  public ReactModuleInfoProvider getReactModuleInfoProvider() {
    return () -> {
      Map<String, ReactModuleInfo> modules = new HashMap<>();
      modules.put(
          BridgeModule.NAME,
          new ReactModuleInfo(
              BridgeModule.NAME,
              BridgeModule.NAME,
              false,
              false,
              false,
              true));
      return modules;
    };
  }
}
