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

PtlcInfo terms(Map<String, dynamic> t) => PtlcInfo(
    id: emptyHash,
    timeLocked: Address.parse(t['timeLocked']),
    tokenStandard: TokenStandard.parse(t['tokenStandard']),
    amount: BigInt.parse(t['amount']),
    expirationTime: t['expirationTime'] as int,
    pointType: t['pointType'] as int,
    pointLock: bytes(t['pointLock']),
    destination: Address.parse(t['destination']));

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
          case 'CreateWithReclaimLock':
            block = api.createWithReclaimLock(
                token(znnZts),
                BigInt.one,
                a[0] as int,
                a[1] as int,
                bytes(a[2]),
                Address.parse(a[3]),
                a[4] as int,
                bytes(a[5]));
            break;
          case 'ReclaimWithSignature':
            block = api.reclaimWithSignature(Hash.parse(a[0]), bytes(a[1]));
            break;
          default:
            fail('no encoder for ${r['method']}');
        }
        expect(hexOf(block.data), r['data'], reason: '${r['method']} $a');
        expect(block.toAddress, ptlcAddress);
        if (!(r['method'] as String).startsWith('Create')) {
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

    test('names the six contract methods', () {
      expect(Definitions.ptlc.entries.map((e) => e.name), [
        'Create',
        'Reclaim',
        'Unlock',
        'ProxyUnlock',
        'CreateWithReclaimLock',
        'ReclaimWithSignature'
      ]);
    });

    test('covers every method', () {
      expect(rows('abi').map((r) => r['method']).toSet(),
          Definitions.ptlc.entries.map((e) => e.name).toSet());
    });
  });

  group('reclaim message', () {
    test('matches go-zenon for every row', () {
      final list = rows('reclaimMessage');
      expect(list.length, greaterThan(100));
      for (final r in list) {
        final message = PtlcApi.reclaimMessageOf(r['chainIdentifier'] as int,
            r['reclaimPointType'] as int, terms(r['terms']));
        expect(hexOf(message), r['message'], reason: '${r['terms']}');
      }
    });

    test('matches the known answers in go-zenon', () {
      Address raw(String value) => Address('z', bytes(value));
      final creator = raw('0022222222222222222222222222222222222222');
      final otherCreator = raw('0033333333333333333333333333333333333333');
      final destination = raw('0044444444444444444444444444444444444444');
      final tokenStandard = TokenStandard.fromBytes(List.filled(10, 0x55));
      final otherToken = TokenStandard.fromBytes(List.filled(10, 0x66));
      PtlcInfo base() => PtlcInfo(
          id: Hash.fromBytes(List.filled(32, 0x11)),
          timeLocked: creator,
          tokenStandard: tokenStandard,
          amount: BigInt.from(0x3b9aca00),
          expirationTime: 1700000000,
          pointType: ptlcPointTypeEd25519,
          pointLock: List.filled(32, 0x11),
          destination: destination);
      void none(PtlcInfo e) {}
      final cases = <List<dynamic>>[
        [69, 0, none, 'b6fd4d7c9f732211766f9e04cbcfc7ed0d57771cddf601645b71ed11fa7e692b'],
        [0, 0, none, '056ef85081335a8a1507920693dbd6266adbe9ba354114a80326fb70501f5dd7'],
        [-1, 0, none, 'b4fa3ba079ea07710c03e82ce84521ddeb1f01d05fc5228bbfbe3ed4f99617bd'],
        [0x0102030405060708, 0, none, '3f7b83457ddfabfb9ea4ddad347e18c7d91b8ffbd29c5d96ee8e0f9a7d979fd6'],
        [69, 1, none, '1cf43f99a8331e729eb7c76ed5370ca466ecb593635ce75e8d491cda7475cadf'],
        [69, 0, (PtlcInfo e) => e.timeLocked = otherCreator, '70e4b33c933980d87ad8c6551f6c4033062bdb62817f3241b27e11db31b8da56'],
        [69, 0, (PtlcInfo e) => e.destination = emptyAddress, '09f9fe595a23a31c62a140993bcce9990f06578e1d7b996792520f5798f2b96b'],
        [69, 0, (PtlcInfo e) => e.tokenStandard = otherToken, '78187a3e26b9373bb2bf72f4c22a5e2f26653d058983c767536d19326615b070'],
        [69, 0, (PtlcInfo e) => e.amount = BigInt.one, 'b51053faab6fac9c5fea266d01c9dfc497ce14dbe5230632c672ca496a3c2698'],
        [69, 0, (PtlcInfo e) => e.amount = (BigInt.one << 256) - BigInt.one, 'a05d1cda114918a1ffdce6f4e8294ab2156c1a16deebaae7e001548abf12f596'],
        [69, 0, (PtlcInfo e) => e.expirationTime = 0x0102030405060708, 'ef413d368802d2c5c130cfa81214934e612a197558d0a036ffd2838f68e1ded2'],
        [
          69,
          0,
          (PtlcInfo e) {
            e.pointType = ptlcPointTypeSecp256k1Point;
            e.pointLock = [0x02, ...List.filled(32, 0x11)];
          },
          'e9f7486805038bdff0696b86b4a169399f2353fe09ed9c4c0262ab8b4a650ac5'
        ],
        [69, 0, (PtlcInfo e) => e.pointLock = List<int>.generate(32, (i) => i), '6ba40a6c48d53de71ae09c2b32638ec174c0d629c5f1c17eaa29e9b5eb0e84c7'],
      ];
      for (final c in cases) {
        final entry = base();
        (c[2] as Function)(entry);
        expect(
            hexOf(PtlcApi.reclaimMessageOf(c[0] as int, c[1] as int, entry)),
            c[3]);
      }
    });

    test('binds the terms, not the id', () {
      final entry = terms(rows('reclaimMessage').first['terms']);
      final message = hexOf(PtlcApi.reclaimMessageOf(69, 1, entry));
      entry.id = Hash.digest([4, 5, 6]);
      expect(hexOf(PtlcApi.reclaimMessageOf(69, 1, entry)), message);
      expect(hexOf(PtlcApi.unlockMessage(69, 1, entry.id, entry.destination)),
          isNot(message));
      expect(hexOf(PtlcApi.reclaimMessageOf(69, 0, entry)), isNot(message));
    });
  });

  group('reclaim lock', () {
    test('is accepted exactly when the contract accepts it', () {
      final list = rows('reclaimLock');
      expect(list.length, greaterThan(200));
      var accepted = 0;
      for (final r in list) {
        final problem = Validations.ptlcReclaimLock(
            r['pointType'] as int, bytes(r['pointLock']));
        expect(problem == null, (r['error'] as String).isEmpty,
            reason:
                'type ${r['pointType']} lock ${r['pointLock']} (${r['note']}): $problem / ${r['error']}');
        if (problem == null) accepted++;
      }
      expect(accepted, greaterThan(50));
    });

    test('refuses a point type, which opens with a scalar', () {
      final point = Secp256k1.scalarToPoint(BigInt.from(7));
      expect(Validations.ptlcPointLock(ptlcPointTypeSecp256k1Point, point),
          isNull);
      expect(Validations.ptlcReclaimLock(ptlcPointTypeSecp256k1Point, point),
          isNotNull);
      expect(Validations.ptlcReclaimLock(ptlcPointTypeBip340, null), isNotNull);
    });

    test('create is accepted exactly when the contract accepts it', () {
      final list = rows('createWithReclaimLock');
      expect(list.length, greaterThan(50));
      for (final r in list) {
        final pointType = r['pointType'] as int;
        final problem =
            Validations.ptlcPointLock(pointType, bytes(r['pointLock'])) ??
                Validations.ptlcDestination(
                    pointType, Address.parse(r['destination'])) ??
                Validations.ptlcReclaimLock(
                    r['reclaimPointType'] as int, bytes(r['reclaimPointLock']));
        expect(problem == null, (r['error'] as String).isEmpty,
            reason: '$r: $problem');
      }
    });

    test('reads and writes the json go-zenon serves', () {
      for (final s in (vectors['reclaimLockInfo'] as List).cast<String>()) {
        final json = jsonDecode(s) as Map<String, dynamic>;
        final lock = PtlcReclaimLock.fromJson(json);
        expect(lock.toJson(), json);
        expect(Validations.ptlcReclaimLock(lock.pointType, lock.pointLock),
            isNull);
      }
    });
  });

  group('reclaim signature', () {
    test('verifies exactly when the contract verifies it', () async {
      final list = rows('reclaimSignature');
      expect(list.length, greaterThan(50));
      var valid = 0;
      for (final r in list) {
        final ok = await PtlcApi.verifyReclaimSignature(
            r['chainIdentifier'] as int,
            terms(r['terms']),
            r['reclaimPointType'] as int,
            bytes(r['reclaimPointLock']),
            bytes(r['signature']));
        expect(ok, (r['error'] as String).isEmpty,
            reason: '${r['note']}: ${r['error']}');
        if (ok) valid++;
      }
      expect(valid, greaterThan(20));
      expect(valid, lessThan(list.length));
    });

    test('has 64 bytes', () {
      expect(Validations.ptlcReclaimSignature(List.filled(64, 0)), isNull);
      expect(Validations.ptlcReclaimSignature(List.filled(65, 0)), isNotNull);
      expect(Validations.ptlcReclaimSignature(List.filled(32, 0)), isNotNull);
      expect(Validations.ptlcReclaimSignature(null), isNotNull);
    });

    test('signatures made here verify for their terms only', () async {
      final entry = terms(rows('reclaimMessage').first['terms']);
      final other = terms(rows('reclaimMessage').first['terms'])
        ..expirationTime += 1;
      final seed = Bip340.sha256([21]);

      final edKey = await Crypto.getPublicKey(seed);
      final edSignature = await Crypto.sign(
          PtlcApi.reclaimMessageOf(69, ptlcPointTypeEd25519, entry),
          seed,
          edKey);
      expect(
          await PtlcApi.verifyReclaimSignature(
              69, entry, ptlcPointTypeEd25519, edKey, edSignature),
          isTrue);
      expect(
          await PtlcApi.verifyReclaimSignature(
              69, other, ptlcPointTypeEd25519, edKey, edSignature),
          isFalse);
      expect(
          await PtlcApi.verifyReclaimSignature(
              3, entry, ptlcPointTypeEd25519, edKey, edSignature),
          isFalse);

      final bipKey = Bip340.publicKey(seed);
      final bipSignature = Bip340.sign(
          seed,
          PtlcApi.reclaimMessageOf(69, ptlcPointTypeBip340, entry),
          Bip340.sha256([22]));
      expect(
          await PtlcApi.verifyReclaimSignature(
              69, entry, ptlcPointTypeBip340, bipKey, bipSignature),
          isTrue);
      expect(
          await PtlcApi.verifyReclaimSignature(
              69, other, ptlcPointTypeBip340, bipKey, bipSignature),
          isFalse);
      expect(
          await PtlcApi.verifyReclaimSignature(
              69, entry, ptlcPointTypeEd25519, bipKey, bipSignature),
          isFalse);
    });

    test(
        'an adaptor pre-signature completes into a reclaim and reveals the secret',
        () async {
      final entry = terms(rows('reclaimMessage').first['terms']);
      final key = Bip340.sha256([31]);
      final reclaimLock = Bip340.publicKey(key);
      final secret = Secp256k1.parseScalar(Bip340.sha256([32]))!;
      final adaptor = Secp256k1.scalarToPoint(secret);
      final message = PtlcApi.reclaimMessageOf(69, ptlcPointTypeBip340, entry);

      final preSignature =
          Bip340.adaptorSign(key, message, adaptor, Bip340.sha256([33]));
      expect(Bip340.adaptorVerify(reclaimLock, message, adaptor, preSignature),
          isTrue);
      expect(
          await PtlcApi.verifyReclaimSignature(69, entry, ptlcPointTypeBip340,
              reclaimLock, preSignature.sublist(0, 64)),
          isFalse);

      final signature = Bip340.adaptorComplete(preSignature, secret);
      expect(
          await PtlcApi.verifyReclaimSignature(
              69, entry, ptlcPointTypeBip340, reclaimLock, signature),
          isTrue);
      expect(Bip340.adaptorExtract(preSignature, signature), secret);
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
