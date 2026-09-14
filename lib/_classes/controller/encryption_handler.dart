// Copyright 2023 The terCAD team. All rights reserved.
// Use of this source code is governed by a CC BY-NC-ND 4.0 license that can be found in the LICENSE file.

import 'dart:convert';
import 'dart:math';

import 'package:app_finance/_classes/storage/app_preferences.dart';
import 'package:crypto/crypto.dart';
import 'package:encrypt/encrypt.dart';

class EncryptionHandler {
  static String prefNotEncrypted = 'false';
  static Encrypter? _cachedEncrypter;

  static Encrypter get salt {
    if (_cachedEncrypter != null) {
      return _cachedEncrypter!;
    }
    
    // Generate or retrieve device-specific encryption key
    String? deviceKey = AppPreferences.get(AppPreferences.prefDeviceKey);
    if (deviceKey == null || deviceKey.isEmpty) {
      // Generate a new random 32-byte key for this device
      final random = Random.secure();
      final keyBytes = List<int>.generate(32, (_) => random.nextInt(256));
      deviceKey = base64Url.encode(keyBytes);
      AppPreferences.set(AppPreferences.prefDeviceKey, deviceKey);
    }
    
    // Decode the base64 key and ensure it's exactly 32 bytes
    final keyBytes = base64Url.decode(deviceKey);
    final key = Key(keyBytes);
    _cachedEncrypter = Encrypter(AES(key));
    return _cachedEncrypter!;
  }

  static IV get code => IV.fromLength(8);

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
    // Generate a random IV for each encryption operation
    final random = Random.secure();
    final ivBytes = List<int>.generate(16, (_) => random.nextInt(256));
    final iv = IV(ivBytes);
    
    // Encrypt the data with the random IV
    final encrypted = salt.encrypt(line, iv: iv);
    
    // Prepend the IV to the ciphertext (IV is not secret, but must be unique)
    // Format: base64(IV) + ':' + base64(ciphertext)
    return '${base64.encode(ivBytes)}:${encrypted.base64}';
  }

  static String decrypt(String line) {
    // Handle legacy format (no IV prefix) for backward compatibility
    if (!line.contains(':')) {
      // Legacy decryption with fixed IV (for existing data)
      return salt.decrypt64(line, iv: code);
    }
    
    // Split IV and ciphertext
    final parts = line.split(':');
    if (parts.length != 2) {
      throw FormatException('Invalid encrypted data format');
    }
    
    // Decode the IV and ciphertext
    final ivBytes = base64.decode(parts[0]);
    final iv = IV(ivBytes);
    final ciphertext = parts[1];
    
    // Decrypt with the extracted IV
    return salt.decrypt64(ciphertext, iv: iv);
  }
}
