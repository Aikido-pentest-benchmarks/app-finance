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
  });

  group('EncryptionHandler', () {
    test('getHash', () {
      Map<String, dynamic> data = {'test': 123};
      // Updated to SHA-256 hash - verify hash is consistent and uses SHA-256
      final hash = EncryptionHandler.getHash(data);
      expect(hash.length, 64); // SHA-256 produces 64 hex characters
      expect(EncryptionHandler.getHash(data), hash); // Verify consistency
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
      // New format includes IV prefix (base64 IV + ':' + base64 ciphertext)
      // Length will vary due to random IV and GCM authentication tag
      expect(enc.contains(':'), true);
      expect(enc.split(':').length, 2);
      expect(EncryptionHandler.decrypt(enc), data);
    });

    test('encrypt produces unique ciphertexts', () {
      String data = 'sample content';
      final enc1 = EncryptionHandler.encrypt(data);
      final enc2 = EncryptionHandler.encrypt(data);
      // Each encryption should produce different ciphertext due to unique IV
      expect(enc1 != enc2, true);
      // But both should decrypt to the same plaintext
      expect(EncryptionHandler.decrypt(enc1), data);
      expect(EncryptionHandler.decrypt(enc2), data);
    });
  });
}
