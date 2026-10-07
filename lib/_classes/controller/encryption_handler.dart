// Copyright 2023 The terCAD team. All rights reserved.
// Use of this source code is governed by a CC BY-NC-ND 4.0 license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:app_finance/_classes/storage/app_preferences.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class EncryptionHandler {
  static String prefNotEncrypted = 'false';
  static String prefEncryptionKey = 'encryptionKey';
  static Key? _cachedKey;
  static final Random _random = Random.secure();

  static Key _getOrGenerateKey() {
    if (_cachedKey != null) {
      return _cachedKey!;
    }

    // Try to retrieve existing key from preferences
    String? storedKey = AppPreferences.get(prefEncryptionKey);
    
    if (storedKey != null && storedKey.isNotEmpty) {
      try {
        // Decode the base64-encoded key
        final keyBytes = base64.decode(storedKey);
        if (keyBytes.length == 32) {
          _cachedKey = Key(Uint8List.fromList(keyBytes));
          return _cachedKey!;
        }
      } catch (e) {
        // If decoding fails, generate a new key
      }
    }

    // Generate a new cryptographically secure random key (256-bit)
    final keyBytes = Uint8List(32);
    for (int i = 0; i < 32; i++) {
      keyBytes[i] = _random.nextInt(256);
    }
    
    _cachedKey = Key(keyBytes);
    
    // Store the key in preferences (base64-encoded)
    AppPreferences.set(prefEncryptionKey, base64.encode(keyBytes));
    
    return _cachedKey!;
  }

  static Encrypter get salt => Encrypter(AES(_getOrGenerateKey(), mode: AESMode.gcm));

  static IV _generateRandomIV() {
    // Generate a cryptographically secure random IV (16 bytes for AES-GCM)
    final ivBytes = Uint8List(16);
    for (int i = 0; i < 16; i++) {
      ivBytes[i] = _random.nextInt(256);
    }
    return IV(ivBytes);
  }

  static String getHash(Map<String, dynamic> data) {
    return getHashString(data.toString());
  }

  static String getHashString(String data) {
    return sha256.convert(utf8.encode(data)).toString();
  }

  static String getHashStringLegacy(String data) {
    return md5.convert(utf8.encode(data)).toString();
  }

  static bool verifyPasswordHash(String password, String storedHash) {
    // Try SHA-256 first (new format)
    if (getHashString(password) == storedHash) {
      return true;
    }
    // Fall back to MD5 for legacy hashes
    if (getHashStringLegacy(password) == storedHash) {
      return true;
    }
    return false;
  }

  static bool doEncrypt() {
    return AppPreferences.get(AppPreferences.prefDoEncrypt) != prefNotEncrypted;
  }

  static String encrypt(String line) {
    // Generate a unique IV for each encryption operation
    final iv = _generateRandomIV();
    
    // Encrypt the data with AES-GCM (provides authentication)
    final encrypted = salt.encrypt(line, iv: iv);
    
    // Prepend the IV to the ciphertext (IV:ciphertext format)
    // IV is not secret and must be transmitted with the ciphertext
    return '${iv.base64}:${encrypted.base64}';
  }

  static String decrypt(String line) {
    try {
      // Split the IV and ciphertext
      final parts = line.split(':');
      if (parts.length != 2) {
        throw Exception('Invalid encrypted data format');
      }
      
      final iv = IV.fromBase64(parts[0]);
      final encryptedData = Encrypted.fromBase64(parts[1]);
      
      // Decrypt using the stored IV
      return salt.decrypt(encryptedData, iv: iv);
    } catch (e) {
      // Attempt legacy decryption for backward compatibility
      return _legacyDecrypt(line);
    }
  }

  // Legacy decryption method for backward compatibility with old data
  static String _legacyDecrypt(String line) {
    try {
      // Use the old hardcoded key and static IV for legacy data
      final legacyKey = Key.fromUtf8('tercad-app-finance-by-vlyskouski');
      final legacyIV = IV.fromLength(8);
      final legacyEncrypter = Encrypter(AES(legacyKey, mode: AESMode.cbc));
      
      return legacyEncrypter.decrypt64(line, iv: legacyIV);
    } catch (e) {
      throw Exception('Failed to decrypt data: ${e.toString()}');
    }
  }
}
