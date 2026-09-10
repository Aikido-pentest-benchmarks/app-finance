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
    // Mock the getString method to return null by default
    when(AppPreferences.pref.getString(any)).thenReturn(null);
    // Mock the setString method to return true
    when(AppPreferences.pref.setString(any, any)).thenAnswer((_) async => true);
  });

  group('EncryptionHandler', () {
    test('getHash uses SHA-256', () {
      Map<String, dynamic> data = {'test': 123};
      // SHA-256 hash is different from MD5
      final hash = EncryptionHandler.getHash(data);
      expect(hash.length, 64); // SHA-256 produces 64 hex characters
    });

    test('encrypt / decrypt with random IV', () {
      String data = 'sample content';
      final enc1 = EncryptionHandler.encrypt(data);
      final enc2 = EncryptionHandler.encrypt(data);
      
      // Each encryption should produce different ciphertext due to random IV
      expect(enc1, isNot(equals(enc2)));
      
      // But both should decrypt to the same plaintext
      expect(EncryptionHandler.decrypt(enc1), data);
      expect(EncryptionHandler.decrypt(enc2), data);
    });

    test('decrypt fails with invalid ciphertext', () {
      expect(
        () => EncryptionHandler.decrypt('invalid_base64_data'),
        throwsException,
      );
    });

    test('decrypt fails with tampered ciphertext', () {
      String data = 'sample content';
      final enc = EncryptionHandler.encrypt(data);
      
      // Tamper with the ciphertext
      final tamperedEnc = enc.substring(0, enc.length - 4) + 'XXXX';
      
      expect(
        () => EncryptionHandler.decrypt(tamperedEnc),
        throwsException,
      );
    });
  });
}
