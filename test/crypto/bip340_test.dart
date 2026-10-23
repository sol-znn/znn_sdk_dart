import 'dart:convert';
import 'dart:io';

import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:znn_sdk_dart/znn_sdk_dart.dart';

List<int> bytes(String value) => HEX.decode(value);

BigInt scalar(int i) => Secp256k1.bytesToBigInt(Bip340.sha256([0x51, i]));

void main() {
  group('BIP-340', () {
    test('official test vectors', () {
      final lines = const LineSplitter()
          .convert(File('test/fixtures/bip340_vectors.csv').readAsStringSync());
      expect(lines.first.startsWith('index,secret key,public key'), isTrue);
      var signed = 0, accepted = 0, rejected = 0;
      for (final line in lines.skip(1)) {
        if (line.trim().isEmpty) continue;
        final f = line.split(',');
        final publicKey = bytes(f[2]);
        final message = bytes(f[4]);
        final signature = bytes(f[5]);
        final expected = f[6] == 'TRUE';
        if (f[1].isNotEmpty) {
          expect(Bip340.publicKey(bytes(f[1])), publicKey, reason: f[0]);
          expect(Bip340.sign(bytes(f[1]), message, bytes(f[3])), signature,
              reason: f[0]);
          signed++;
        }
        expect(Bip340.verify(publicKey, message, signature), expected,
            reason: '${f[0]} ${f.length > 7 ? f[7] : ''}');
        expected ? accepted++ : rejected++;
      }
      expect(signed, greaterThanOrEqualTo(4));
      expect(accepted, greaterThanOrEqualTo(5));
      expect(rejected, greaterThanOrEqualTo(10));
    });

    test('refuses malformed input', () {
      final key = Secp256k1.scalarToBytes(scalar(1));
      final message = Bip340.sha256([1]);
      final signature = Bip340.sign(key, message, Bip340.sha256([2]));
      final publicKey = Bip340.publicKey(key);
      expect(Bip340.verify(publicKey, message, signature), isTrue);
      expect(Bip340.verify(publicKey.sublist(1), message, signature), isFalse);
      expect(Bip340.verify(publicKey, message, signature.sublist(1)), isFalse);
      expect(Bip340.verify(publicKey, Bip340.sha256([3]), signature), isFalse);
      expect(() => Bip340.sign(List.filled(32, 0), message, Bip340.sha256([2])),
          throwsArgumentError);
      expect(() => Bip340.sign(key, message, [1, 2, 3]), throwsArgumentError);
    });
  });

  group('adaptor signatures', () {
    for (var i = 1; i <= 8; i++) {
      test('pre-sign, verify, complete and extract ($i)', () {
        final key = Secp256k1.scalarToBytes(scalar(i));
        final publicKey = Bip340.publicKey(key);
        final secret = scalar(100 + i);
        final adaptor = Secp256k1.scalarToPoint(secret);
        final message = Bip340.sha256([0x42, i]);

        final presig =
            Bip340.adaptorSign(key, message, adaptor, Bip340.sha256([0x43, i]));
        expect(presig.length, 65);
        expect(
            Bip340.adaptorVerify(publicKey, message, adaptor, presig), isTrue);
        expect(Bip340.verify(publicKey, message, presig.sublist(1)), isFalse);

        final signature = Bip340.adaptorComplete(presig, secret);
        expect(Bip340.verify(publicKey, message, signature), isTrue);
        expect(Bip340.adaptorExtract(presig, signature), secret);
      });
    }

    test('a pre-signature binds key, message and adaptor', () {
      final key = Secp256k1.scalarToBytes(scalar(1));
      final publicKey = Bip340.publicKey(key);
      final adaptor = Secp256k1.scalarToPoint(scalar(2));
      final message = Bip340.sha256([1]);
      final presig =
          Bip340.adaptorSign(key, message, adaptor, Bip340.sha256([2]));
      expect(
          Bip340.adaptorVerify(
              Bip340.publicKey(Secp256k1.scalarToBytes(scalar(3))),
              message,
              adaptor,
              presig),
          isFalse);
      expect(
          Bip340.adaptorVerify(publicKey, Bip340.sha256([4]), adaptor, presig),
          isFalse);
      expect(
          Bip340.adaptorVerify(
              publicKey, message, Secp256k1.scalarToPoint(scalar(5)), presig),
          isFalse);
      final tampered = List<int>.from(presig);
      tampered[64] ^= 1;
      expect(
          Bip340.adaptorVerify(publicKey, message, adaptor, tampered), isFalse);
      final wrong = Bip340.adaptorComplete(presig, scalar(6));
      expect(Bip340.verify(publicKey, message, wrong), isFalse);
    });

    test('one secret opens two tweaked points', () {
      final secret = scalar(7);
      final tweak = scalar(8);
      final point = Secp256k1.scalarToPoint(secret);
      final tweaked = Secp256k1.tweakPoint(point, tweak);
      expect(tweaked,
          Secp256k1.scalarToPoint(Secp256k1.tweakScalar(secret, tweak)));
      expect(tweaked, isNot(point));
    });
  });

  group('secp256k1', () {
    test('parses only canonical scalars', () {
      expect(Secp256k1.parseScalar(List.filled(32, 0)), isNull);
      expect(
          Secp256k1.parseScalar(Secp256k1.scalarToBytes(Secp256k1.n)), isNull);
      expect(
          Secp256k1.parseScalar(
              Secp256k1.scalarToBytes(Secp256k1.n - BigInt.one)),
          Secp256k1.n - BigInt.one);
      expect(Secp256k1.parseScalar(List.filled(31, 1)), isNull);
    });

    test('the generator is the point of one', () {
      expect(HEX.encode(Secp256k1.scalarToPoint(BigInt.one)),
          '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    });

    test('parses only compressed points', () {
      final point = Secp256k1.scalarToPoint(scalar(9));
      expect(Secp256k1.parseCompressed(point), isNotNull);
      expect(Secp256k1.parseCompressed([0x04, ...point.sublist(1)]), isNull);
      expect(Secp256k1.parseCompressed(point.sublist(1)), isNull);
      expect(Secp256k1.parseCompressed(List.filled(33, 0)), isNull);
    });
  });
}
