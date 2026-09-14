// Copyright 2023 The terCAD team. All rights reserved.
// Use of this source code is governed by a CC BY-NC-ND 4.0 license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:math';

import 'package:app_finance/_classes/storage/app_preferences.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class EncryptionHandler {
  static String prefNotEncrypted = 'false';
  static Encrypter? _encrypter;
  static final _random = Random.secure();
  static bool _initialized = false;

  // Legacy encrypter for backward compatibility with old data
  static Encrypter get _legacySalt => Encrypter(AES(Key.fromUtf8('tercad-app-finance-by-vlyskouski')));
  static IV get _legacyCode => IV.fromLength(8);

  // Initialize encryption key - should be called during app startup
  static Future<void> initialize() async {
    if (_initialized) {
      return;
    }
    
    // Try to get existing key from preferences
    String? storedKey = AppPreferences.get(AppPreferences.prefEncryptionKey);
    
    if (storedKey == null || storedKey.isEmpty) {
      // Generate new secure random key (32 bytes for AES-256)
      final keyBytes = List<int>.generate(32, (_) => _random.nextInt(256));
      storedKey = base64.encode(keyBytes);
      await AppPreferences.set(AppPreferences.prefEncryptionKey, storedKey);
    }
    
    final keyBytes = base64.decode(storedKey);
    _encrypter = Encrypter(AES(Key(keyBytes)));
    _initialized = true;
  }

  // Get or create per-installation encryption key
  static Encrypter get salt {
    if (_encrypter != null) {
      return _encrypter!;
    }
    
    // Fallback: Try to get existing key from preferences synchronously
    String? storedKey = AppPreferences.get(AppPreferences.prefEncryptionKey);
    
    if (storedKey == null || storedKey.isEmpty) {
      // Generate new secure random key (32 bytes for AES-256)
      final keyBytes = List<int>.generate(32, (_) => _random.nextInt(256));
      storedKey = base64.encode(keyBytes);
      // Note: This async call won't be awaited, but the key is already generated
      // and will be used immediately. The persistence happens in the background.
      AppPreferences.set(AppPreferences.prefEncryptionKey, storedKey);
    }
    
    final keyBytes = base64.decode(storedKey);
    _encrypter = Encrypter(AES(Key(keyBytes)));
    return _encrypter!;
  }

  // Generate a cryptographically secure random IV for each encryption operation
  static IV generateIV() {
    final ivBytes = List<int>.generate(16, (_) => _random.nextInt(256));
    return IV(ivBytes);
  }

  static String getHash(Map<String, dynamic> data) {
    return getHashString(data.toString());
  }

  static String getHashString(String data) {
    return sha256.convert(utf8.encode(data)).toString();
  }

  static bool doEncrypt() {
    // Always return true - encryption is now mandatory for security
    return true;
  }

  static String encrypt(String line) {
    final iv = generateIV();
    final encrypted = salt.encrypt(line, iv: iv);
    // Prepend IV to ciphertext for use during decryption
    return base64.encode(iv.bytes + base64.decode(encrypted.base64));
  }

  static String decrypt(String line) {
    try {
      // Try new format first (IV prepended to ciphertext)
      final combined = base64.decode(line);
      if (combined.length > 16) {
        final iv = IV(combined.sublist(0, 16));
        final ciphertext = base64.encode(combined.sublist(16));
        return salt.decrypt64(ciphertext, iv: iv);
      }
    } catch (e) {
      // Fall through to legacy decryption
    }
    
    // Fallback to legacy decryption for backward compatibility
    try {
      return _legacySalt.decrypt64(line, iv: _legacyCode);
    } catch (e) {
      // If both fail, rethrow the exception
      rethrow;
    }
  }
}
