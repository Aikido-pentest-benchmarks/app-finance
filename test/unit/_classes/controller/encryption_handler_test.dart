// Copyright 2023 The terCAD team. All rights reserved.
// Use of this source code is governed by a CC BY-NC-ND 4.0 license that can be found in the LICENSE file.

import 'package:app_finance/_classes/controller/encryption_handler.dart';
import 'package:app_finance/_classes/storage/app_preferences.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';
import 'package:shared_preferences/shared_preferences.dart';

@GenerateNiceMocks([MockSpec<SharedPreferences>()])
import 'encryption_handler_test.mocks.dart';

void main() {
  setUp(() {
    AppPreferences.pref = MockSharedPreferences();
    // Allow the mock to accept setString calls for encryption key storage
    when(AppPreferences.pref.setString(any, any)).thenAnswer((_) async => true);
  });

  group('EncryptionHandler', () {
    test('getHash', () {
      Map<String, dynamic> data = {'test': 123};
      // SHA256 produces a 64-character hex string
      final hash = EncryptionHandler.getHash(data);
      expect(hash.length, 64);
      // Verify hash is consistent
      expect(EncryptionHandler.getHash(data), hash);
    });

    group('doEncrypt', () {
      final testCases = [
        (getPreference: null, result: true),
        (getPreference: 'true', result: true),
        (getPreference: 'false', result: false),
      ];

      for (var v in testCases) {
        test('$v', () {
          when(AppPreferences.pref.getString('doEncrypt')).thenReturn(v.getPreference);
          expect(EncryptionHandler.doEncrypt(), v.result);
        });
      }
    });

    test('encrypt / decrypt', () {
      String data = 'sample content';
      final enc = EncryptionHandler.encrypt(data);
      // New format produces longer output due to envelope structure (version, IV, ciphertext)
      expect(enc.length, greaterThan(50));
      expect(EncryptionHandler.decrypt(enc), data);
    });

    test('encrypt produces different ciphertexts for same plaintext', () {
      String data = 'sample content';
      final enc1 = EncryptionHandler.encrypt(data);
      final enc2 = EncryptionHandler.encrypt(data);
      // Due to random IVs, same plaintext should produce different ciphertexts
      expect(enc1, isNot(equals(enc2)));
      // But both should decrypt to the same plaintext
      expect(EncryptionHandler.decrypt(enc1), data);
      expect(EncryptionHandler.decrypt(enc2), data);
    });
  });
}
