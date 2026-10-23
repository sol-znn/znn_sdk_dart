import 'dart:typed_data';

import 'package:pointycastle/ecc/api.dart';
import 'package:pointycastle/ecc/curves/secp256k1.dart';

class Secp256k1 {
  static final ECDomainParameters params = ECCurve_secp256k1();

  static final BigInt n = params.n;

  static final BigInt p = BigInt.parse(
      'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F',
      radix: 16);

  static ECPoint get g => params.G;

  static Uint8List scalarToBytes(BigInt s) => bigIntToBytes(s, 32);

  static BigInt? parseScalar(List<int> bytes) {
    if (bytes.length != 32) return null;
    final s = bytesToBigInt(bytes);
    if (s == BigInt.zero || s >= n) return null;
    return s;
  }

  static Uint8List scalarToPoint(BigInt t) =>
      Uint8List.fromList((g * (t % n))!.getEncoded(true));

  static ECPoint? parseCompressed(List<int> bytes) {
    if (bytes.length != 33 || (bytes[0] != 0x02 && bytes[0] != 0x03)) {
      return null;
    }
    if (bytesToBigInt(bytes.sublist(1)) >= p) return null;
    try {
      final point = params.curve.decodePoint(bytes);
      if (point == null || point.isInfinity) return null;
      return point;
    } catch (_) {
      return null;
    }
  }

  static ECPoint? liftX(List<int> xOnly) {
    if (xOnly.length != 32) return null;
    return parseCompressed([0x02, ...xOnly]);
  }

  static Uint8List xOnly(ECPoint point) =>
      bigIntToBytes(point.x!.toBigInteger()!, 32);

  static bool hasEvenY(ECPoint point) => point.y!.toBigInteger()!.isEven;

  static Uint8List compress(ECPoint point) =>
      Uint8List.fromList(point.getEncoded(true));

  static Uint8List tweakPoint(List<int> compressed, BigInt d) {
    final t = parseCompressed(compressed);
    if (t == null) throw ArgumentError('not a compressed secp256k1 point');
    final sum = (t + (g * (d % n)))!;
    if (sum.isInfinity) throw ArgumentError('tweak cancels the point');
    return compress(sum);
  }

  static BigInt tweakScalar(BigInt t, BigInt d) => (t + d) % n;

  static Uint8List bigIntToBytes(BigInt value, int length) {
    if (value.isNegative) throw ArgumentError('negative');
    final out = Uint8List(length);
    var v = value;
    for (var i = length - 1; i >= 0; i--) {
      out[i] = (v & BigInt.from(0xff)).toInt();
      v = v >> 8;
    }
    if (v != BigInt.zero) throw ArgumentError('value does not fit');
    return out;
  }

  static BigInt bytesToBigInt(List<int> bytes) {
    var v = BigInt.zero;
    for (final b in bytes) {
      v = (v << 8) | BigInt.from(b & 0xff);
    }
    return v;
  }
}
