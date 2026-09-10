// Copyright 2023 The terCAD team. All rights reserved.
// Use of this source code is governed by a CC BY-NC-ND 4.0 license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:app_finance/_classes/storage/app_preferences.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class EncryptionHandler {
  static const String _prefEncryptionKey = 'encryption_key_v2';
  static const int _keyLength = 32; // 256 bits for AES-256
  static const int _ivLength = 16; // 128 bits for AES-GCM
  static Key? _cachedKey;
  static final Random _secureRandom = Random.secure();

  /// Generates or retrieves the application-specific encryption key
  static Key _getOrCreateKey() {
    if (_cachedKey != null) {
      return _cachedKey!;
    }

    String? storedKey = AppPreferences.get(_prefEncryptionKey);
    if (storedKey != null && storedKey.isNotEmpty) {
      try {
        _cachedKey = Key(base64.decode(storedKey));
        return _cachedKey!;
      } catch (e) {
        // If key is corrupted, generate a new one
      }
    }

    // Generate a new secure random key
    final keyBytes = Uint8List(_keyLength);
    for (int i = 0; i < _keyLength; i++) {
      keyBytes[i] = _secureRandom.nextInt(256);
    }
    _cachedKey = Key(keyBytes);
    AppPreferences.set(_prefEncryptionKey, base64.encode(keyBytes));
    return _cachedKey!;
  }

  /// Generates a cryptographically secure random IV
  static IV _generateIV() {
    final ivBytes = Uint8List(_ivLength);
    for (int i = 0; i < _ivLength; i++) {
      ivBytes[i] = _secureRandom.nextInt(256);
    }
    return IV(ivBytes);
  }

  static Encrypter get _encrypter => Encrypter(AES(_getOrCreateKey(), mode: AESMode.gcm));

  static String getHash(Map<String, dynamic> data) {
    return getHashString(data.toString());
  }

  static String getHashString(String data) {
    return sha256.convert(utf8.encode(data)).toString();
  }

  /// Encrypts data with authenticated encryption (AES-GCM)
  /// Returns: base64(iv || ciphertext || tag)
  static String encrypt(String line) {
    final iv = _generateIV();
    final encrypted = _encrypter.encrypt(line, iv: iv);
    
    // Combine IV + ciphertext + tag for storage
    // Format: base64(iv || encrypted_data_with_tag)
    final combined = Uint8List.fromList([
      ...iv.bytes,
      ...encrypted.bytes,
    ]);
    
    return base64.encode(combined);
  }

  /// Decrypts and verifies authenticated ciphertext
  /// Throws exception if authentication fails
  static String decrypt(String line) {
    try {
      final combined = base64.decode(line);
      
      if (combined.length < _ivLength) {
        throw Exception('Invalid ciphertext: too short');
      }
      
      // Extract IV and ciphertext+tag
      final iv = IV(Uint8List.fromList(combined.sublist(0, _ivLength)));
      final ciphertext = Uint8List.fromList(combined.sublist(_ivLength));
      
      // Decrypt and verify authentication tag
      final decrypted = _encrypter.decrypt(Encrypted(ciphertext), iv: iv);
      return decrypted;
    } catch (e) {
      throw Exception('Decryption failed: authentication verification failed or corrupted data');
    }
  }

  /// Legacy method for backward compatibility - kept for hash verification
  static String decrypt64(String line, {IV? iv}) {
    return decrypt(line);
  }
}
