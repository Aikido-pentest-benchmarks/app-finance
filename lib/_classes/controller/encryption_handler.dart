// Copyright 2023 The terCAD team. All rights reserved.
// Use of this source code is governed by a CC BY-NC-ND 4.0 license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:math';

import 'package:app_finance/_classes/storage/app_preferences.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class EncryptionHandler {
  static String prefNotEncrypted = 'false';
  static const String prefEncryptionKey = 'encryptionKey';
  static const int encryptionVersion = 1;
  static final Random _random = Random.secure();

  // Generate or retrieve a per-installation encryption key
  static Key _getOrCreateKey() {
    String? storedKey = AppPreferences.get(prefEncryptionKey);
    if (storedKey == null || storedKey.isEmpty) {
      // Generate a new 256-bit (32-byte) key
      final keyBytes = List<int>.generate(32, (_) => _random.nextInt(256));
      storedKey = base64.encode(keyBytes);
      // Store asynchronously but use the key immediately
      // The key will be available for future sessions
      AppPreferences.set(prefEncryptionKey, storedKey);
    }
    return Key.fromBase64(storedKey);
  }

  static Encrypter get salt => Encrypter(AES(_getOrCreateKey(), mode: AESMode.gcm));

  // Generate a random IV for each encryption operation
  static IV _generateRandomIV() {
    final ivBytes = List<int>.generate(16, (_) => _random.nextInt(256));
    return IV.fromBase64(base64.encode(ivBytes));
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

  static String encrypt(String line) {
    final iv = _generateRandomIV();
    final encrypted = salt.encrypt(line, iv: iv);
    
    // Create an authenticated envelope with version, IV, and ciphertext
    final envelope = {
      'v': encryptionVersion,
      'iv': iv.base64,
      'ct': encrypted.base64,
    };
    
    return base64.encode(utf8.encode(json.encode(envelope)));
  }

  static String decrypt(String line) {
    try {
      // Try to parse as new envelope format
      final envelopeJson = utf8.decode(base64.decode(line));
      final envelope = json.decode(envelopeJson) as Map<String, dynamic>;
      
      if (envelope.containsKey('v') && envelope.containsKey('iv') && envelope.containsKey('ct')) {
        // New format with versioning and random IV
        final iv = IV.fromBase64(envelope['iv'] as String);
        final ciphertext = envelope['ct'] as String;
        return salt.decrypt64(ciphertext, iv: iv);
      }
    } catch (e) {
      // Fall back to legacy format for backward compatibility
      try {
        // Legacy format: direct base64 ciphertext with static IV
        final legacyKey = Key.fromUtf8('tercad-app-finance-by-vlyskouski');
        final legacyEncrypter = Encrypter(AES(legacyKey));
        final legacyIV = IV.fromLength(8);
        return legacyEncrypter.decrypt64(line, iv: legacyIV);
      } catch (legacyError) {
        rethrow;
      }
    }
    
    throw Exception('Failed to decrypt: invalid format');
  }
}
