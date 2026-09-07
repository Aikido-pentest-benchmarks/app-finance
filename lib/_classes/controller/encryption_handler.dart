// Copyright 2023 The terCAD team. All rights reserved.
// Use of this source code is governed by a CC BY-NC-ND 4.0 license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:math';

import 'package:app_finance/_classes/storage/app_preferences.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class EncryptionHandler {
  static String prefNotEncrypted = 'false';
  static const String _prefEncryptionKey = 'encryptionKey';
  static const int _ivLength = 16; // AES block size

  // Generate or retrieve a device-specific encryption key
  static Key _getEncryptionKey() {
    String? storedKey = AppPreferences.get(_prefEncryptionKey);
    
    if (storedKey == null || storedKey.isEmpty) {
      // Generate a new random 256-bit key
      final random = Random.secure();
      final keyBytes = List<int>.generate(32, (_) => random.nextInt(256));
      storedKey = base64.encode(keyBytes);
      AppPreferences.set(_prefEncryptionKey, storedKey);
    }
    
    return Key(base64.decode(storedKey));
  }

  static Encrypter get salt => Encrypter(AES(_getEncryptionKey()));

  // Generate a random IV for each encryption operation
  static IV _generateRandomIV() {
    final random = Random.secure();
    final ivBytes = List<int>.generate(_ivLength, (_) => random.nextInt(256));
    return IV.fromBase64(base64.encode(ivBytes));
  }

  static String getHash(Map<String, dynamic> data) {
    return getHashString(data.toString());
  }

  static String getHashString(String data) {
    return md5.convert(utf8.encode(data)).toString();
  }

  static bool doEncrypt() {
    return AppPreferences.get(AppPreferences.prefDoEncrypt) != prefNotEncrypted;
  }

  static String encrypt(String line) {
    // Generate a random IV for this encryption
    final iv = _generateRandomIV();
    final encrypted = salt.encrypt(line, iv: iv);
    
    // Prepend IV to ciphertext (IV:ciphertext format)
    return '${iv.base64}:${encrypted.base64}';
  }

  static String decrypt(String line) {
    try {
      // Check if the line contains an IV (new format)
      if (line.contains(':')) {
        final parts = line.split(':');
        if (parts.length == 2) {
          final iv = IV.fromBase64(parts[0]);
          final ciphertext = parts[1];
          return salt.decrypt64(ciphertext, iv: iv);
        }
      }
      
      // Fallback to legacy format with fixed IV for backward compatibility
      final legacyIV = IV.fromLength(8);
      return salt.decrypt64(line, iv: legacyIV);
    } catch (e) {
      // If decryption fails with new key, try legacy key for migration
      try {
        final legacyKey = Key.fromUtf8('tercad-app-finance-by-vlyskouski');
        final legacyEncrypter = Encrypter(AES(legacyKey));
        final legacyIV = IV.fromLength(8);
        return legacyEncrypter.decrypt64(line, iv: legacyIV);
      } catch (_) {
        rethrow;
      }
    }
  }
}
