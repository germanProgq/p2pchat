// Android payload conversion helpers. Spec: app/bridge/BridgeSpec.md.
package com.p2pchat.bridge;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.Dynamic;
import com.facebook.react.bridge.ReadableArray;
import com.facebook.react.bridge.ReadableMap;
import com.facebook.react.bridge.ReadableType;
import com.facebook.react.bridge.WritableArray;
import com.facebook.react.bridge.WritableMap;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.ByteBuffer;
import java.util.Iterator;

final class BridgePayloads {
  private BridgePayloads() {
  }

  static byte[] bytesFromObject(Object value) {
    if (value == null) {
      return null;
    }
    if (value instanceof byte[]) {
      return (byte[]) value;
    }
    if (value instanceof ByteBuffer) {
      ByteBuffer buffer = ((ByteBuffer) value).slice();
      byte[] out = new byte[buffer.remaining()];
      buffer.get(out);
      return out;
    }
    if (value instanceof ReadableArray) {
      return bytesFromReadableArray((ReadableArray) value);
    }
    if (value instanceof ReadableMap) {
      ReadableMap map = (ReadableMap) value;
      if (map.hasKey("data") && map.getType("data") == ReadableType.Array) {
        return bytesFromReadableArray(map.getArray("data"));
      }
    }
    if (value instanceof String) {
      String text = (String) value;
      return android.util.Base64.decode(text, android.util.Base64.DEFAULT);
    }
    throw new IllegalArgumentException("Unsupported binary payload");
  }

  static byte[] bytesFromDynamic(Dynamic dynamic) {
    if (dynamic == null || dynamic.isNull()) {
      return null;
    }
    ReadableType type = dynamic.getType();
    if (type == ReadableType.String) {
      return dynamic.asString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }
    if (type == ReadableType.Array) {
      return bytesFromReadableArray(dynamic.asArray());
    }
    if (type == ReadableType.Map) {
      return bytesFromObject(dynamic.asMap());
    }
    throw new IllegalArgumentException("Unsupported payload type");
  }

  static byte[] bytesFromReadableArray(ReadableArray array) {
    if (array == null) {
      return null;
    }
    byte[] out = new byte[array.size()];
    for (int i = 0; i < array.size(); i++) {
      if (array.isNull(i)) {
        out[i] = 0;
        continue;
      }
      if (array.getType(i) == ReadableType.Number) {
        out[i] = (byte) array.getDouble(i);
      } else {
        out[i] = 0;
      }
    }
    return out;
  }

  static Object payloadFromJson(String json) {
    if (json == null) {
      return null;
    }
    String trimmed = json.trim();
    if (trimmed.isEmpty()) {
      return null;
    }
    try {
      char start = trimmed.charAt(0);
      if (start == '{') {
        return toWritableMap(new JSONObject(trimmed));
      }
      if (start == '[') {
        return toWritableArray(new JSONArray(trimmed));
      }
      return null;
    } catch (JSONException e) {
      throw new IllegalArgumentException("Invalid JSON payload", e);
    }
  }

  static WritableArray historyArrayFromJson(String json) {
    Object payload = payloadFromJson(json);
    if (payload instanceof WritableArray) {
      return (WritableArray) payload;
    }
    return Arguments.createArray();
  }

  private static WritableMap toWritableMap(JSONObject object) throws JSONException {
    WritableMap map = Arguments.createMap();
    Iterator<String> keys = object.keys();
    while (keys.hasNext()) {
      String key = keys.next();
      Object value = object.get(key);
      putJsonValue(map, key, value);
    }
    return map;
  }

  private static WritableArray toWritableArray(JSONArray array) throws JSONException {
    WritableArray out = Arguments.createArray();
    for (int i = 0; i < array.length(); i++) {
      Object value = array.get(i);
      pushJsonValue(out, value);
    }
    return out;
  }

  private static void putJsonValue(WritableMap map, String key, Object value) throws JSONException {
    if (value == null || value == JSONObject.NULL) {
      map.putNull(key);
      return;
    }
    if (value instanceof JSONObject) {
      map.putMap(key, toWritableMap((JSONObject) value));
      return;
    }
    if (value instanceof JSONArray) {
      map.putArray(key, toWritableArray((JSONArray) value));
      return;
    }
    if (value instanceof Boolean) {
      map.putBoolean(key, (Boolean) value);
      return;
    }
    if (value instanceof Integer) {
      map.putInt(key, (Integer) value);
      return;
    }
    if (value instanceof Long) {
      map.putDouble(key, ((Long) value).doubleValue());
      return;
    }
    if (value instanceof Double) {
      map.putDouble(key, (Double) value);
      return;
    }
    if (value instanceof Number) {
      map.putDouble(key, ((Number) value).doubleValue());
      return;
    }
    map.putString(key, value.toString());
  }

  private static void pushJsonValue(WritableArray array, Object value) throws JSONException {
    if (value == null || value == JSONObject.NULL) {
      array.pushNull();
      return;
    }
    if (value instanceof JSONObject) {
      array.pushMap(toWritableMap((JSONObject) value));
      return;
    }
    if (value instanceof JSONArray) {
      array.pushArray(toWritableArray((JSONArray) value));
      return;
    }
    if (value instanceof Boolean) {
      array.pushBoolean((Boolean) value);
      return;
    }
    if (value instanceof Integer) {
      array.pushInt((Integer) value);
      return;
    }
    if (value instanceof Long) {
      array.pushDouble(((Long) value).doubleValue());
      return;
    }
    if (value instanceof Double) {
      array.pushDouble((Double) value);
      return;
    }
    if (value instanceof Number) {
      array.pushDouble(((Number) value).doubleValue());
      return;
    }
    array.pushString(value.toString());
  }
}
