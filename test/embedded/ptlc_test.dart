import 'dart:convert';
import 'dart:io';

import 'package:hex/hex.dart';
import 'package:test/test.dart';
import 'package:znn_sdk_dart/src/crypto/ed25519.dart' show Ed25519;
import 'package:znn_sdk_dart/znn_sdk_dart.dart';

final Map<String, dynamic> vectors =
    jsonDecode(File('test/fixtures/ptlc_vectors.json').readAsStringSync());

List<Map<String, dynamic>> rows(String name) =>
    (vectors[name] as List).cast<Map<String, dynamic>>();

List<int> bytes(String value) => HEX.decode(value);

String hexOf(List<int> value) => HEX.encode(value);

Token token(TokenStandard tokenStandard) => Token(
    'Zenon',
    'ZNN',
    'zenon.network',
    BigInt.zero,
    8,
    emptyAddress,
    tokenStandard,
    BigInt.zero,
    true,
    true,
    true);

void main() {
  group('contract address', () {
    test('is the embedded ptlc address', () {
      expect(
          ptlcAddress.toString(), 'z1qxemdeddedxptlcxxxxxxxxxxxxxxxxx6lqady');
    });

    test('is an embedded contract', () {
      expect(ptlcAddress.isEmbedded(), isTrue);
      expect(embeddedContractAddresses, contains(htlcAddress));
      expect(embeddedContractAddresses, contains(ptlcAddress));
    });
  });

  group('unlock message', () {
    test('matches go-zenon for every row', () {
      final list = rows('unlockMessage');
      expect(list.length, greaterThan(100));
      for (final r in list) {
        final message = PtlcApi.unlockMessage(
            r['chainIdentifier'] as int,
            r['pointType'] as int,
            Hash.parse(r['id']),
            Address.parse(r['destination']));
        expect(hexOf(message), r['message'],
            reason:
                '${r['chainIdentifier']}/${r['pointType']}/${r['id']}/${r['destination']}');
      }
    });

    test('binds every field', () {
      final id = Hash.parse(rows('unlockMessage').first['id']);
      final base = hexOf(PtlcApi.unlockMessage(69, 1, id, emptyAddress));
      expect(
          hexOf(PtlcApi.unlockMessage(70, 1, id, emptyAddress)), isNot(base));
      expect(
          hexOf(PtlcApi.unlockMessage(69, 0, id, emptyAddress)), isNot(base));
      expect(
          hexOf(PtlcApi.unlockMessage(69, 1, Hash.digest([1]), emptyAddress)),
          isNot(base));
      expect(hexOf(PtlcApi.unlockMessage(69, 1, id, htlcAddress)), isNot(base));
    });
  });

  group('point lock', () {
    test('is accepted exactly when the contract accepts it', () {
      final list = rows('pointLock');
      expect(list.length, greaterThan(200));
      var accepted = 0;
      for (final r in list) {
        final problem = Validations.ptlcPointLock(
            r['pointType'] as int, bytes(r['pointLock']));
        expect(problem == null, (r['error'] as String).isEmpty,
            reason:
                'type ${r['pointType']} lock ${r['pointLock']} (${r['note']}): $problem / ${r['error']}');
        if (problem == null) accepted++;
      }
      expect(accepted, greaterThan(50));
      expect(accepted, lessThan(list.length));
    });

    test('refuses every Ed25519 point of small order', () {
      for (final r
          in rows('pointLock').where((r) => r['note'] == 'small order')) {
        expect(Ed25519Point.isValidLock(bytes(r['pointLock'])), isFalse,
            reason: r['pointLock']);
      }
    });

    test('takes an Ed25519 key with a torsion component', () {
      final mixed = rows('pointLock')
          .where((r) => r['note'] == 'key plus torsion')
          .toList();
      expect(mixed, isNotEmpty);
      for (final r in mixed) {
        expect(Ed25519Point.isValidLock(bytes(r['pointLock'])), isTrue);
      }
    });

    test('refuses a null value', () {
      expect(Validations.ptlcPointLock(ptlcPointTypeBip340, null), isNotNull);
    });
  });

  group('create', () {
    test('is accepted exactly when the contract accepts it', () {
      for (final r in rows('create')) {
        final pointType = r['pointType'] as int;
        final problem =
            Validations.ptlcPointLock(pointType, bytes(r['pointLock'])) ??
                Validations.ptlcDestination(
                    pointType, Address.parse(r['destination']));
        expect(problem == null, (r['error'] as String).isEmpty,
            reason:
                'type $pointType destination ${r['destination']}: $problem / ${r['error']}');
      }
    });

    test('a point lock needs a destination', () {
      expect(
          Validations.ptlcDestination(
              ptlcPointTypeSecp256k1Point, emptyAddress),
          isNotNull);
      expect(Validations.ptlcDestination(ptlcPointTypeEd25519, emptyAddress),
          isNull);
      expect(Validations.ptlcDestination(ptlcPointTypeBip340, emptyAddress),
          isNull);
    });

    test('a destination must be a user address', () {
      for (final contract in embeddedContractAddresses) {
        for (final pointType in ptlcPointLockSizes.keys) {
          expect(Validations.ptlcDestination(pointType, contract), isNotNull);
        }
      }
    });
  });

  group('witness', () {
    test('verifies exactly when the contract verifies it', () async {
      final list = rows('witness');
      expect(list.length, greaterThan(80));
      for (final r in list) {
        final ok = await PtlcApi.verifyWitness(
            r['chainIdentifier'] as int,
            r['pointType'] as int,
            bytes(r['pointLock']),
            Hash.parse(r['id']),
            Address.parse(r['destination']),
            bytes(r['witness']));
        expect(ok, (r['error'] as String).isEmpty,
            reason: 'type ${r['pointType']} (${r['note']}): ${r['error']}');
      }
    });

    test('refuses an Ed25519 signature with s at or above the group order',
        () async {
      final r = rows('witness').firstWhere((r) =>
          r['pointType'] == ptlcPointTypeEd25519 && r['note'] == 'valid');
      final signature = bytes(r['witness']);
      var s = BigInt.zero;
      for (var i = 63; i >= 32; i--) {
        s = (s << 8) | BigInt.from(signature[i]);
      }
      var t = s + Ed25519.l;
      final malleated = List<int>.from(signature);
      for (var i = 32; i < 64; i++) {
        malleated[i] = (t & BigInt.from(0xff)).toInt();
        t = t >> 8;
      }
      expect(
          await PtlcApi.verifyWitness(
              r['chainIdentifier'] as int,
              ptlcPointTypeEd25519,
              bytes(r['pointLock']),
              Hash.parse(r['id']),
              Address.parse(r['destination']),
              signature),
          isTrue);
      expect(
          await PtlcApi.verifyWitness(
              r['chainIdentifier'] as int,
              ptlcPointTypeEd25519,
              bytes(r['pointLock']),
              Hash.parse(r['id']),
              Address.parse(r['destination']),
              malleated),
          isFalse);
    });

    test('signatures made here verify for their entry only', () async {
      final id = Hash.digest([1, 2, 3]);
      final destination = Address.parse(rows('create')[1]['destination']);
      final other = Address.parse(rows('create')[2]['destination']);

      final seed = Bip340.sha256([7]);
      final edKey = await Crypto.getPublicKey(seed);
      final edMessage =
          PtlcApi.unlockMessage(69, ptlcPointTypeEd25519, id, destination);
      final edSignature = await Crypto.sign(edMessage, seed, edKey);
      expect(
          await PtlcApi.verifyWitness(
              69, ptlcPointTypeEd25519, edKey, id, destination, edSignature),
          isTrue);
      expect(
          await PtlcApi.verifyWitness(
              69, ptlcPointTypeEd25519, edKey, id, other, edSignature),
          isFalse);

      final bipKey = Bip340.publicKey(seed);
      final bipSignature = Bip340.sign(
          seed,
          PtlcApi.unlockMessage(69, ptlcPointTypeBip340, id, destination),
          Bip340.sha256([8]));
      expect(
          await PtlcApi.verifyWitness(
              69, ptlcPointTypeBip340, bipKey, id, destination, bipSignature),
          isTrue);
      expect(
          await PtlcApi.verifyWitness(
              3, ptlcPointTypeBip340, bipKey, id, destination, bipSignature),
          isFalse);

      final point = Secp256k1.scalarToPoint(Secp256k1.parseScalar(seed)!);
      expect(
          await PtlcApi.verifyWitness(
              69, ptlcPointTypeSecp256k1Point, point, id, destination, seed),
          isTrue);
      expect(
          await PtlcApi.verifyWitness(69, ptlcPointTypeSecp256k1Point, point,
              id, destination, Bip340.sha256([9])),
          isFalse);
    });

    test('has the size of its point type', () {
      expect(Validations.ptlcWitness(ptlcPointTypeEd25519, List.filled(64, 0)),
          isNull);
      expect(Validations.ptlcWitness(ptlcPointTypeBip340, List.filled(64, 0)),
          isNull);
      expect(
          Validations.ptlcWitness(
              ptlcPointTypeSecp256k1Point, List.filled(32, 0)),
          isNull);
      expect(Validations.ptlcWitness(ptlcPointTypeBip340, List.filled(32, 0)),
          isNotNull);
      expect(
          Validations.ptlcWitness(
              ptlcPointTypeSecp256k1Point, List.filled(64, 0)),
          isNotNull);
      expect(Validations.ptlcWitness(3, List.filled(64, 0)), isNotNull);
    });
  });

  group('abi', () {
    test('encodes every call as go-zenon does', () {
      final api = PtlcApi();
      for (final r in rows('abi')) {
        final a = r['args'] as List;
        late AccountBlockTemplate block;
        switch (r['method']) {
          case 'Create':
            block = api.create(token(znnZts), BigInt.one, a[0] as int,
                a[1] as int, bytes(a[2]), Address.parse(a[3]));
            break;
          case 'Reclaim':
            block = api.reclaim(Hash.parse(a[0]));
            break;
          case 'Unlock':
            block = api.unlock(Hash.parse(a[0]), bytes(a[1]));
            break;
          case 'ProxyUnlock':
            block = api.proxyUnlock(
                Hash.parse(a[0]), Address.parse(a[1]), bytes(a[2]));
            break;
        }
        expect(hexOf(block.data), r['data'], reason: '${r['method']} $a');
        expect(block.toAddress, ptlcAddress);
        if (r['method'] != 'Create') {
          expect(block.amount, BigInt.zero);
        }
      }
    });

    test('decodes every call go-zenon encodes', () {
      for (final r in rows('abi')) {
        final a = r['args'] as List;
        final decoded =
            Definitions.ptlc.decodeFunction(bytes(r['data'])) as List;
        expect(decoded.length, a.length);
        for (var i = 0; i < a.length; i++) {
          final value = decoded[i];
          final got = value is List<int> ? hexOf(value) : value.toString();
          expect(got, a[i].toString(), reason: '${r['method']} arg $i');
        }
      }
    });

    test('names the four contract methods', () {
      expect(Definitions.ptlc.entries.map((e) => e.name),
          ['Create', 'Reclaim', 'Unlock', 'ProxyUnlock']);
    });
  });

  group('PtlcInfo', () {
    test('reads and writes the json go-zenon serves', () {
      for (final s in (vectors['info'] as List).cast<String>()) {
        final json = jsonDecode(s) as Map<String, dynamic>;
        final info = PtlcInfo.fromJson(json);
        expect(info.toJson(), json);
        expect(info.amount.toString(), '123456789012345678901234567890');
        expect(info.hasFixedDestination,
            info.pointType == ptlcPointTypeSecp256k1Point);
        expect(
            Validations.ptlcPointLock(info.pointType, info.pointLock), isNull);
      }
    });
  });
}
