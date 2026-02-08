import 'dart:convert';
import 'dart:typed_data';

import 'package:basic_utils/basic_utils.dart';
import 'package:pointycastle/export.dart';

import 'encrypt_request.dart';

class EncryptDecryptHelper {
  /// Encrypt data with hybrid encryption (AES + RSA)
  static EncryptRequest encrypt(String data, String publicKey) {
    // Generate AES key and IV
    final aesKey = _generateAesKey();
    final iv = _generateIV();

    // Encrypt data with AES
    final encryptedData = _encryptData(data, aesKey, iv);

    // Encrypt AES key with RSA
    final encryptedAesKey = _encryptAesKey(aesKey, publicKey);

    return EncryptRequest(
      data: encryptedData,
      aes: encryptedAesKey,
      iv: base64Encode(iv),
    );
  }

  /// Decrypt data with hybrid encryption (AES + RSA)
  static String decrypt(EncryptRequest request, String privateKey) {
    // Decrypt AES key with RSA
    final aesKey = _decryptAesKey(request.aes!, privateKey);

    // Decrypt data with AES
    return _decryptData(
      request.data,
      aesKey,
      base64Decode(request.iv),
    );
  }

  /// Generate random 256-bit AES key
  static Uint8List _generateAesKey() {
    final secureRandom = _getSecureRandom();
    return secureRandom.nextBytes(32); // 256 bits
  }

  /// Generate random 128-bit IV
  static Uint8List _generateIV() {
    final secureRandom = _getSecureRandom();
    return secureRandom.nextBytes(16); // 128 bits
  }

  /// Get secure random number generator
  static SecureRandom _getSecureRandom() {
    final secureRandom = FortunaRandom();
    final seedSource = DateTime.now().millisecondsSinceEpoch;
    final seed = Uint8List.fromList(
      List.generate(32, (i) => (seedSource + i * 7) % 256),
    );
    secureRandom.seed(KeyParameter(seed));
    return secureRandom;
  }

  /// Encrypt plaintext with AES-256-CBC
  static String _encryptData(String plaintext, Uint8List key, Uint8List iv) {
    final cipher = CBCBlockCipher(AESEngine())
      ..init(true, ParametersWithIV(KeyParameter(key), iv));

    final plaintextBytes = utf8.encode(plaintext);
    final paddedPlaintext = _addPKCS7Padding(plaintextBytes, 16);
    final ciphertext = Uint8List(paddedPlaintext.length);

    for (var offset = 0; offset < paddedPlaintext.length; offset += 16) {
      cipher.processBlock(paddedPlaintext, offset, ciphertext, offset);
    }

    return base64Encode(ciphertext);
  }

  /// Decrypt ciphertext with AES-256-CBC
  static String _decryptData(String ciphertext, Uint8List key, Uint8List iv) {
    final ciphertextBytes = base64Decode(ciphertext);

    final cipher = CBCBlockCipher(AESEngine())
      ..init(false, ParametersWithIV(KeyParameter(key), iv));

    final decrypted = Uint8List(ciphertextBytes.length);

    for (var offset = 0; offset < ciphertextBytes.length; offset += 16) {
      cipher.processBlock(ciphertextBytes, offset, decrypted, offset);
    }

    final unpaddedDecrypted = _removePKCS7Padding(decrypted);
    return utf8.decode(unpaddedDecrypted);
  }

  /// Add PKCS7 padding
  static Uint8List _addPKCS7Padding(List<int> data, int blockSize) {
    final padLength = blockSize - (data.length % blockSize);
    final padded = Uint8List(data.length + padLength);
    padded.setAll(0, data);
    for (var i = data.length; i < padded.length; i++) {
      padded[i] = padLength;
    }
    return padded;
  }

  /// Remove PKCS7 padding
  static Uint8List _removePKCS7Padding(Uint8List data) {
    final padLength = data.last;
    return data.sublist(0, data.length - padLength);
  }

  /// Encrypt AES key with RSA-OAEP-SHA256
  static String _encryptAesKey(Uint8List aesKey, String publicKey) {
    // Parse public key from PEM (handle escaped newlines from env)
    final pemKey = publicKey.replaceAll(r'\n', '\n');
    final rsaPublicKey = CryptoUtils.rsaPublicKeyFromPem(pemKey);

    // Encrypt with RSA-OAEP-SHA256
    final encryptor = OAEPEncoding.withSHA256(RSAEngine())
      ..init(true, PublicKeyParameter<RSAPublicKey>(rsaPublicKey));

    final encrypted = encryptor.process(aesKey);
    return base64Encode(encrypted);
  }

  /// Decrypt AES key with RSA-OAEP-SHA256
  static Uint8List _decryptAesKey(String encryptedAesKey, String privateKey) {
    final encryptedAesKeyBytes = base64Decode(encryptedAesKey);

    // Parse private key from PEM (handle escaped newlines from env)
    final pemKey = privateKey.replaceAll(r'\n', '\n');
    final rsaPrivateKey = CryptoUtils.rsaPrivateKeyFromPem(pemKey);

    // Decrypt with RSA-OAEP-SHA256
    final decryptor = OAEPEncoding.withSHA256(RSAEngine())
      ..init(false, PrivateKeyParameter<RSAPrivateKey>(rsaPrivateKey));

    return decryptor.process(encryptedAesKeyBytes);
  }
}
