import 'dart:typed_data';

import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/ecc/api.dart';
import 'package:znn_sdk_dart/src/crypto/secp256k1.dart';

class Bip340 {
  static const String _auxTag = 'BIP0340/aux';
  static const String _nonceTag = 'BIP0340/nonce';
  static const String _challengeTag = 'BIP0340/challenge';
  static const String _adaptorAuxTag = 'zenon/ptlc/adaptor-aux';

  static Uint8List sha256(List<int> data) =>
      SHA256Digest().process(Uint8List.fromList(data));

  static Uint8List taggedHash(String tag, List<int> msg) {
    final tagHash = sha256(Uint8List.fromList(tag.codeUnits));
    return sha256([...tagHash, ...tagHash, ...msg]);
  }

  static Uint8List publicKey(List<int> secretKey) {
    final d = _secret(secretKey);
    return Secp256k1.xOnly((Secp256k1.g * d)!);
  }

  static Uint8List sign(
      List<int> secretKey, List<int> message, List<int> auxRand) {
    _check32(auxRand, 'auxRand');
    final d0 = _secret(secretKey);
    final pPoint = (Secp256k1.g * d0)!;
    final d = Secp256k1.hasEvenY(pPoint) ? d0 : Secp256k1.n - d0;
    final pBytes = Secp256k1.xOnly(pPoint);

    final k = _nonce(d, pBytes, message, auxRand);
    final rPoint = (Secp256k1.g * k)!;
    final kFinal = Secp256k1.hasEvenY(rPoint) ? k : Secp256k1.n - k;
    final rBytes = Secp256k1.xOnly(rPoint);

    final e = _challenge(rBytes, pBytes, message);
    final s = (kFinal + e * d) % Secp256k1.n;
    final signature =
        Uint8List.fromList([...rBytes, ...Secp256k1.scalarToBytes(s)]);
    if (!verify(pBytes, message, signature)) {
      throw StateError('the signature does not verify');
    }
    return signature;
  }

  static bool verify(
      List<int> publicKey, List<int> message, List<int> signature) {
    if (publicKey.length != 32 || signature.length != 64) {
      return false;
    }
    final pPoint = Secp256k1.liftX(publicKey);
    if (pPoint == null) return false;
    final r = Secp256k1.bytesToBigInt(signature.sublist(0, 32));
    if (r >= Secp256k1.p) return false;
    final s = Secp256k1.bytesToBigInt(signature.sublist(32));
    if (s >= Secp256k1.n) return false;
    final e = _challenge(signature.sublist(0, 32), publicKey, message);
    final rPoint = _add(Secp256k1.g * s, pPoint * (Secp256k1.n - e));
    if (rPoint == null || rPoint.isInfinity) return false;
    if (!Secp256k1.hasEvenY(rPoint)) return false;
    return rPoint.x!.toBigInteger()! == r;
  }

  static Uint8List adaptorSign(List<int> secretKey, List<int> message,
      List<int> adaptor, List<int> auxRand) {
    _check32(auxRand, 'auxRand');
    final tPoint = Secp256k1.parseCompressed(adaptor);
    if (tPoint == null) {
      throw ArgumentError('adaptor is not a compressed point');
    }
    final d0 = _secret(secretKey);
    final pPoint = (Secp256k1.g * d0)!;
    final d = Secp256k1.hasEvenY(pPoint) ? d0 : Secp256k1.n - d0;
    final pBytes = Secp256k1.xOnly(pPoint);

    final aux = taggedHash(_adaptorAuxTag, [...auxRand, ...adaptor]);
    final k0 = _nonce(d, pBytes, message, aux);
    final rPrime = (Secp256k1.g * k0)!;
    final rPoint = (rPrime + tPoint)!;
    if (rPoint.isInfinity) throw StateError('nonce cancels the adaptor');
    final k = Secp256k1.hasEvenY(rPoint) ? k0 : Secp256k1.n - k0;
    final e = _challenge(Secp256k1.xOnly(rPoint), pBytes, message);
    final sPrime = (k + e * d) % Secp256k1.n;
    final presig = Uint8List.fromList(
        [...Secp256k1.compress(rPoint), ...Secp256k1.scalarToBytes(sPrime)]);
    if (!adaptorVerify(pBytes, message, adaptor, presig)) {
      throw StateError('the pre-signature does not verify');
    }
    return presig;
  }

  static bool adaptorVerify(List<int> publicKey, List<int> message,
      List<int> adaptor, List<int> presig) {
    if (publicKey.length != 32 || presig.length != 65) {
      return false;
    }
    final pPoint = Secp256k1.liftX(publicKey);
    final tPoint = Secp256k1.parseCompressed(adaptor);
    final rPoint = Secp256k1.parseCompressed(presig.sublist(0, 33));
    if (pPoint == null || tPoint == null || rPoint == null) return false;
    final sPrime = Secp256k1.bytesToBigInt(presig.sublist(33));
    if (sPrime >= Secp256k1.n) return false;
    final e = _challenge(Secp256k1.xOnly(rPoint), publicKey, message);
    final ePoint = pPoint * e;
    final expected = Secp256k1.hasEvenY(rPoint)
        ? _add(rPoint - tPoint, ePoint)
        : _add(tPoint - rPoint, ePoint);
    final actual = Secp256k1.g * sPrime;
    if (expected == null || actual == null || expected.isInfinity) {
      return false;
    }
    return expected == actual;
  }

  static Uint8List adaptorComplete(List<int> presig, BigInt secret) {
    if (presig.length != 65) throw ArgumentError('malformed pre-signature');
    final rPoint = Secp256k1.parseCompressed(presig.sublist(0, 33));
    if (rPoint == null) throw ArgumentError('malformed pre-signature');
    final sPrime = Secp256k1.bytesToBigInt(presig.sublist(33));
    final s = Secp256k1.hasEvenY(rPoint)
        ? (sPrime + secret) % Secp256k1.n
        : (sPrime - secret) % Secp256k1.n;
    return Uint8List.fromList(
        [...Secp256k1.xOnly(rPoint), ...Secp256k1.scalarToBytes(s)]);
  }

  static BigInt adaptorExtract(List<int> presig, List<int> signature) {
    if (presig.length != 65) throw ArgumentError('malformed pre-signature');
    final rPoint = Secp256k1.parseCompressed(presig.sublist(0, 33));
    if (rPoint == null) throw ArgumentError('malformed pre-signature');
    if (signature.length != 64) throw ArgumentError('malformed signature');
    final sPrime = Secp256k1.bytesToBigInt(presig.sublist(33));
    final s = Secp256k1.bytesToBigInt(signature.sublist(32));
    return Secp256k1.hasEvenY(rPoint)
        ? (s - sPrime) % Secp256k1.n
        : (sPrime - s) % Secp256k1.n;
  }

  static ECPoint? _add(ECPoint? a, ECPoint? b) {
    if (a == null || b == null) return null;
    return a + b;
  }

  static BigInt _secret(List<int> secretKey) {
    final d = Secp256k1.parseScalar(secretKey);
    if (d == null) {
      throw ArgumentError('secret key is not a canonical scalar');
    }
    return d;
  }

  static BigInt _nonce(
      BigInt d, List<int> pBytes, List<int> message, List<int> auxRand) {
    final tBytes = Secp256k1.scalarToBytes(d);
    final auxHash = taggedHash(_auxTag, auxRand);
    final t = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      t[i] = tBytes[i] ^ auxHash[i];
    }
    final rand = taggedHash(_nonceTag, [...t, ...pBytes, ...message]);
    final k = Secp256k1.bytesToBigInt(rand) % Secp256k1.n;
    if (k == BigInt.zero) throw StateError('zero nonce');
    return k;
  }

  static BigInt _challenge(
          List<int> rBytes, List<int> pBytes, List<int> message) =>
      Secp256k1.bytesToBigInt(
          taggedHash(_challengeTag, [...rBytes, ...pBytes, ...message])) %
      Secp256k1.n;

  static void _check32(List<int> value, String name) {
    if (value.length != 32) throw ArgumentError('$name must be 32 bytes');
  }
}
