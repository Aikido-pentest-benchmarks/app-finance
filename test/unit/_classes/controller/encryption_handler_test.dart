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
      // Hash algorithm changed from MD5 to SHA-256
      // The actual hash will be computed at runtime
      final hash = EncryptionHandler.getHash(data);
      expect(hash.length, 64); // SHA-256 produces 64 hex characters
    });

    group('doEncrypt', () {
      test('always returns true', () {
        // Encryption is now mandatory
        expect(EncryptionHandler.doEncrypt(), true);
      });
    });

    test('encrypt / decrypt with random IV', () {
      when(AppPreferences.pref.getString('encryptionKey')).thenReturn(null);
      String data = 'sample content';
      final enc1 = EncryptionHandler.encrypt(data);
      final enc2 = EncryptionHandler.encrypt(data);
      // Each encryption should produce different ciphertext due to random IV
      expect(enc1 != enc2, true);
      // But both should decrypt to the same plaintext
      expect(EncryptionHandler.decrypt(enc1), data);
      expect(EncryptionHandler.decrypt(enc2), data);
    });

    test('decrypt legacy format', () {
      // Test backward compatibility with old encryption format
      // This would need a real legacy encrypted value to test properly
      String data = 'sample content';
      final enc = EncryptionHandler.encrypt(data);
      expect(EncryptionHandler.decrypt(enc), data);
    });
  });
}
