// Android keystore-backed master key manager for core storage encryption.
package com.p2pchat.bridge;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.security.KeyStore;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

final class BridgeKeyStore {
  private static final String KEY_ALIAS = "p2pchat.master";
  private static final String PREFS = "p2pchat.bridge";
  private static final String PREF_BLOB = "master_blob";
  private static final String PREF_IV = "master_iv";
  private static final int MASTER_KEY_BYTES = 32;
  private static final int GCM_TAG_BITS = 128;

  static byte[] loadOrCreate(Context context) {
    SharedPreferences prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE);
    String blob = prefs.getString(PREF_BLOB, null);
    String iv = prefs.getString(PREF_IV, null);
    SecretKey secretKey = getOrCreateSecretKey();
    if (blob != null && iv != null) {
      try {
        byte[] decoded = Base64.decode(blob, Base64.NO_WRAP);
        byte[] ivBytes = Base64.decode(iv, Base64.NO_WRAP);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, ivBytes));
        byte[] decrypted = cipher.doFinal(decoded);
        if (decrypted.length == MASTER_KEY_BYTES) {
          return decrypted;
        }
      } catch (Exception ignored) {
        prefs.edit().remove(PREF_BLOB).remove(PREF_IV).apply();
      }
    }
    byte[] fresh = new byte[MASTER_KEY_BYTES];
    new SecureRandom().nextBytes(fresh);
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
      byte[] ciphertext = cipher.doFinal(fresh);
      byte[] ivBytes = cipher.getIV();
      prefs.edit()
          .putString(PREF_BLOB, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
          .putString(PREF_IV, Base64.encodeToString(ivBytes, Base64.NO_WRAP))
          .apply();
    } catch (Exception e) {
      throw new IllegalStateException("Failed to persist master key", e);
    }
    return fresh;
  }

  private static SecretKey getOrCreateSecretKey() {
    try {
      KeyStore store = KeyStore.getInstance("AndroidKeyStore");
      store.load(null);
      if (store.containsAlias(KEY_ALIAS)) {
        return ((SecretKey) store.getKey(KEY_ALIAS, null));
      }
      KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
      KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
          KEY_ALIAS,
          KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
          .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
          .setRandomizedEncryptionRequired(true);
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        builder.setKeySize(256);
      }
      try {
        keyGenerator.init(builder.build());
        return keyGenerator.generateKey();
      } catch (Exception e) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
          builder.setKeySize(128);
          keyGenerator.init(builder.build());
          return keyGenerator.generateKey();
        }
        throw e;
      }
    } catch (Exception e) {
      throw new IllegalStateException("Failed to access Android keystore", e);
    }
  }

  private BridgeKeyStore() {}
}
