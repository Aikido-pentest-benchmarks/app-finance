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
  static const String _prefEncryptionKey = 'encryptionKey';
  static Key? _cachedKey;
  static final Random _random = Random.secure();

  /// Generates or retrieves the per-installation encryption key.
  /// The key is stored in SharedPreferences and generated once per installation.
  static Key _getOrCreateKey() {
    if (_cachedKey != null) {
      return _cachedKey!;
    }

    String? storedKey = AppPreferences.get(_prefEncryptionKey);
    if (storedKey != null && storedKey.isNotEmpty) {
      try {
        _cachedKey = Key.fromBase64(storedKey);
        return _cachedKey!;
      } catch (e) {
        // If key is corrupted, generate a new one
      }
    }

    // Generate a new 256-bit (32-byte) key
    final keyBytes = List<int>.generate(32, (_) => _random.nextInt(256));
    _cachedKey = Key(Uint8List.fromList(keyBytes));
    
    // Store the key for future use
    AppPreferences.set(_prefEncryptionKey, _cachedKey!.base64);
    
    return _cachedKey!;
  }

  static Encrypter get salt => Encrypter(AES(_getOrCreateKey(), mode: AESMode.gcm));

  /// Generates a random IV for each encryption operation.
  /// Using a unique IV for each encryption is critical for security.
  static IV _generateRandomIV() {
    final ivBytes = List<int>.generate(16, (_) => _random.nextInt(256));
    return IV(Uint8List.fromList(ivBytes));
  }

  static String getHash(Map<String, dynamic> data) {
    return getHashString(data.toString());
  }

  static String getHashString(String data) {
    return sha256.convert(utf8.encode(data)).toString();
  }

  static bool doEncrypt() {
    return AppPreferences.get(AppPreferences.prefDoEncrypt) != prefNotEncrypted;
  }

  /// Encrypts data with AES-GCM using a random IV.
  /// The IV is prepended to the ciphertext for later decryption.
  /// Format: [IV (16 bytes)][Ciphertext]
  static String encrypt(String line) {
    final iv = _generateRandomIV();
    final encrypted = salt.encrypt(line, iv: iv);
    
    // Prepend IV to the ciphertext (both in base64)
    // Format: IV_base64:ciphertext_base64
    return '${iv.base64}:${encrypted.base64}';
  }

  /// Decrypts data encrypted with the encrypt() method.
  /// Extracts the IV from the beginning of the ciphertext.
  static String decrypt(String line) {
    try {
      // Split IV and ciphertext
      final parts = line.split(':');
      if (parts.length != 2) {
        // Fallback for legacy data encrypted with the old method
        return _decryptLegacy(line);
      }
      
      final iv = IV.fromBase64(parts[0]);
      final ciphertext = parts[1];
      
      return salt.decrypt64(ciphertext, iv: iv);
    } catch (e) {
      // Attempt legacy decryption as fallback
      return _decryptLegacy(line);
    }
  }

  /// Legacy decryption method for backward compatibility with old encrypted data.
  /// This uses the old hardcoded key and zero IV.
  /// WARNING: This is insecure and only provided for migration purposes.
  static String _decryptLegacy(String line) {
    final legacyKey = Key.fromUtf8('tercad-app-finance-by-vlyskouski');
    final legacyIV = IV.fromLength(8);
    final legacyEncrypter = Encrypter(AES(legacyKey, mode: AESMode.cbc));
    
    return legacyEncrypter.decrypt64(line, iv: legacyIV);
  }
}
