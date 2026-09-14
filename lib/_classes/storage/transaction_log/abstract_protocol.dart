// Copyright 2023 The terCAD team. All rights reserved.
// Use of this source code is governed by a CC BY-NC-ND 4.0 license that can be found in the LICENSE file.

import 'package:app_finance/_classes/controller/encryption_handler.dart';
import 'package:app_finance/_classes/storage/transaction_log.dart';

abstract class AbstractProtocol {
  Future<List<int>> exportTransactions([bool forceEncryption = false]) async {
    List<int> codeUnits = [];
    await for (String line in TransactionLog.read()) {
      String exportLine = line;
      // If forceEncryption is true and the line is not already encrypted, encrypt it
      if (forceEncryption && !_isEncrypted(line)) {
        exportLine = EncryptionHandler.encrypt(line);
      }
      codeUnits.addAll(exportLine.codeUnits);
      codeUnits.addAll('\n'.codeUnits);
    }
    return codeUnits;
  }

  bool _isEncrypted(String line) {
    // Encrypted lines are base64 encoded and typically don't start with '{' or '['
    // which are common JSON starting characters
    if (line.isEmpty) return false;
    try {
      // Try to decrypt - if it fails, it's not encrypted
      EncryptionHandler.decrypt(line);
      return true;
    } catch (e) {
      return false;
    }
  }

  void clearTransactions() => TransactionLog.clear();

  void importTransactions(List<int> codeUnits, [bool isEncrypted = true]) {
    List<String> lines = String.fromCharCodes(codeUnits).split('\n');
    for (String line in lines) {
      if (line.trim() == '') {
        continue;
      }
      try {
        if (isEncrypted) {
          line = EncryptionHandler.decrypt(line);
        }
        TransactionLog.save(line);
      } catch (e) {
        // ... ignore failures
      }
    }
  }
}
