import 'dart:io';

import 'package:test/test.dart';
import 'package:znn_sdk_dart/znn_sdk_dart.dart';

final String? node = Platform.environment['PTLC_NODE'];
final String? mnemonic = Platform.environment['PTLC_MNEMONIC'];
final int accountIndex =
    int.parse(Platform.environment['PTLC_ACCOUNT_INDEX'] ?? '1');

final znn = Zenon();
late KeyPair creator;
late Address self;
late Address other;
late int chainIdentifier;

Future<Momentum> frontier() => znn.ledger.getFrontierMomentum();

Future<AccountBlock> confirmedReceive(Hash sendHash) async {
  for (var i = 0; i < 120; i++) {
    final block = await znn.ledger.getAccountBlockByHash(sendHash);
    final receive = block?.pairedAccountBlock;
    if (block?.confirmationDetail != null && receive != null) {
      final confirmed = await znn.ledger.getAccountBlockByHash(receive.hash);
      if (confirmed?.confirmationDetail != null) {
        return confirmed!;
      }
    }
    await Future.delayed(const Duration(seconds: 2));
  }
  throw StateError('$sendHash was not received by the contract');
}

bool accepted(AccountBlock receive) =>
    receive.data.length == 8 &&
    Secp256k1.bytesToBigInt(receive.data) == BigInt.one;

Future<AccountBlock> call(AccountBlockTemplate template) async {
  final sent = await znn.send(template, currentKeyPair: creator);
  return confirmedReceive(sent.hash);
}

Future<Hash> create(int pointType, List<int> pointLock, Address destination,
    {int seconds = 3600}) async {
  expect(Validations.ptlcPointLock(pointType, pointLock), isNull);
  expect(Validations.ptlcDestination(pointType, destination), isNull);
  final expirationTime = (await frontier()).timestamp + seconds;
  final sent = await znn.send(
      znn.embedded.ptlc.create(await token(), BigInt.one, expirationTime,
          pointType, pointLock, destination),
      currentKeyPair: creator);
  final receive = await confirmedReceive(sent.hash);
  expect(accepted(receive), isTrue, reason: 'create type $pointType');
  final info = await znn.embedded.ptlc.getById(sent.hash);
  expect(info.id, sent.hash);
  expect(info.timeLocked, self);
  expect(info.tokenStandard, znnZts);
  expect(info.amount, BigInt.one);
  expect(info.expirationTime, expirationTime);
  expect(info.pointType, pointType);
  expect(info.pointLock, pointLock);
  expect(info.destination, destination);
  return sent.hash;
}

Future<Token> token() async => (await znn.embedded.token.getByZts(znnZts))!;

void expectPayout(AccountBlock receive, Address to) {
  expect(accepted(receive), isTrue);
  expect(receive.descendantBlocks.length, 1);
  final payout = receive.descendantBlocks.single;
  expect(payout.toAddress, to);
  expect(payout.amount, BigInt.one);
  expect(payout.tokenStandard, znnZts);
}

Future<void> expectGone(Hash id) async {
  await expectLater(znn.embedded.ptlc.getById(id), throwsA(anything));
}

Future<void> expectRefusedAtPublish(AccountBlockTemplate template) async {
  await expectLater(
      znn.send(template, currentKeyPair: creator), throwsA(anything));
}

void main() {
  final skip = node == null || mnemonic == null
      ? 'PTLC_NODE and PTLC_MNEMONIC are not set'
      : false;

  group('ptlc on a live node', () {
    setUpAll(() async {
      await znn.wsClient.initialize(node!, retry: false);
      chainIdentifier = (await frontier()).chainIdentifier;
      setChainIdentifier(chainIdentifier: chainIdentifier);
      final keyStore = KeyStore.fromMnemonic(mnemonic!);
      creator = keyStore.getKeyPair(accountIndex);
      self = (await creator.address)!;
      other = (await keyStore.getKeyPair(accountIndex + 1).address)!;
    });

    tearDownAll(() {
      znn.wsClient.stop();
    });

    test('an Ed25519 key lock opens with a signature for the caller',
        () async {
      final seed = Bip340.sha256([1, ...DateTime.now().toString().codeUnits]);
      final key = await Crypto.getPublicKey(seed);
      final id = await create(ptlcPointTypeEd25519, key, emptyAddress);
      final signature = await Crypto.sign(
          PtlcApi.unlockMessage(
              chainIdentifier, ptlcPointTypeEd25519, id, self),
          seed,
          key);
      expect(
          await PtlcApi.verifyWitness(chainIdentifier, ptlcPointTypeEd25519,
              key, id, self, signature),
          isTrue);
      expectPayout(await call(znn.embedded.ptlc.unlock(id, signature)), self);
      await expectGone(id);
    });

    test('a BIP-340 key lock opens with a signature for the caller', () async {
      final secret = Bip340.sha256([2, ...DateTime.now().toString().codeUnits]);
      final key = Bip340.publicKey(secret);
      final id = await create(ptlcPointTypeBip340, key, emptyAddress);
      final signature = Bip340.sign(
          secret,
          PtlcApi.unlockMessage(chainIdentifier, ptlcPointTypeBip340, id, self),
          Bip340.sha256([3]));
      expectPayout(await call(znn.embedded.ptlc.unlock(id, signature)), self);
      await expectGone(id);
    });

    test('a secp256k1 point lock opens with its scalar', () async {
      final secret = Bip340.sha256([4, ...DateTime.now().toString().codeUnits]);
      final point = Secp256k1.scalarToPoint(Secp256k1.parseScalar(secret)!);
      final id = await create(ptlcPointTypeSecp256k1Point, point, self);
      expectPayout(await call(znn.embedded.ptlc.unlock(id, secret)), self);
      await expectGone(id);
    });

    test('a proxy unlock pays the destination the witness names', () async {
      final secret = Bip340.sha256([5, ...DateTime.now().toString().codeUnits]);
      final key = Bip340.publicKey(secret);
      final id = await create(ptlcPointTypeBip340, key, emptyAddress);
      final forSelf = Bip340.sign(
          secret,
          PtlcApi.unlockMessage(chainIdentifier, ptlcPointTypeBip340, id, self),
          Bip340.sha256([6]));
      final refused =
          await call(znn.embedded.ptlc.proxyUnlock(id, other, forSelf));
      expect(accepted(refused), isFalse);
      expect(refused.descendantBlocks, isEmpty);
      final forOther = Bip340.sign(
          secret,
          PtlcApi.unlockMessage(
              chainIdentifier, ptlcPointTypeBip340, id, other),
          Bip340.sha256([7]));
      expectPayout(
          await call(znn.embedded.ptlc.proxyUnlock(id, other, forOther)),
          other);
      await expectGone(id);
    });

    test('a point lock pays only its fixed destination', () async {
      final secret = Bip340.sha256([8, ...DateTime.now().toString().codeUnits]);
      final point = Secp256k1.scalarToPoint(Secp256k1.parseScalar(secret)!);
      final id = await create(ptlcPointTypeSecp256k1Point, point, other);
      final refused = await call(znn.embedded.ptlc.unlock(id, secret));
      expect(accepted(refused), isFalse);
      expect((await znn.embedded.ptlc.getById(id)).destination, other);
      expectPayout(
          await call(znn.embedded.ptlc.proxyUnlock(id, other, secret)), other);
      await expectGone(id);
    });

    test('an adaptor signature completes into the unlock witness', () async {
      final secret = Bip340.sha256([9, ...DateTime.now().toString().codeUnits]);
      final key = Bip340.publicKey(secret);
      final adaptorSecret = Secp256k1.parseScalar(Bip340.sha256([10]))!;
      final adaptor = Secp256k1.scalarToPoint(adaptorSecret);
      final id = await create(ptlcPointTypeBip340, key, emptyAddress);
      final message =
          PtlcApi.unlockMessage(chainIdentifier, ptlcPointTypeBip340, id, self);
      final presig =
          Bip340.adaptorSign(secret, message, adaptor, Bip340.sha256([11]));
      expect(Bip340.adaptorVerify(key, message, adaptor, presig), isTrue);
      final witness = Bip340.adaptorComplete(presig, adaptorSecret);
      final sent = await znn.send(znn.embedded.ptlc.unlock(id, witness),
          currentKeyPair: creator);
      expectPayout(await confirmedReceive(sent.hash), self);
      final published = await znn.ledger.getAccountBlockByHash(sent.hash);
      final args = Definitions.ptlc.decodeFunction(published!.data) as List;
      expect(Bip340.adaptorExtract(presig, args[1] as List<int>), adaptorSecret);
    });

    test('a wrong witness is refused and the entry stays', () async {
      final secret =
          Bip340.sha256([12, ...DateTime.now().toString().codeUnits]);
      final point = Secp256k1.scalarToPoint(Secp256k1.parseScalar(secret)!);
      final id = await create(ptlcPointTypeSecp256k1Point, point, self);
      final wrong = Bip340.sha256([13]);
      expect(
          await PtlcApi.verifyWitness(chainIdentifier,
              ptlcPointTypeSecp256k1Point, point, id, self, wrong),
          isFalse);
      final refused = await call(znn.embedded.ptlc.unlock(id, wrong));
      expect(accepted(refused), isFalse);
      expect(refused.descendantBlocks, isEmpty);
      expect((await znn.embedded.ptlc.getById(id)).id, id);
      final early = await call(znn.embedded.ptlc.reclaim(id));
      expect(accepted(early), isFalse);
      expectPayout(await call(znn.embedded.ptlc.unlock(id, secret)), self);
    });

    test('an expired entry refuses unlock and is reclaimed by its creator',
        () async {
      final secret =
          Bip340.sha256([14, ...DateTime.now().toString().codeUnits]);
      final point = Secp256k1.scalarToPoint(Secp256k1.parseScalar(secret)!);
      final id =
          await create(ptlcPointTypeSecp256k1Point, point, self, seconds: 40);
      final info = await znn.embedded.ptlc.getById(id);
      while ((await frontier()).timestamp < info.expirationTime + 10) {
        await Future.delayed(const Duration(seconds: 5));
      }
      final late = await call(znn.embedded.ptlc.unlock(id, secret));
      expect(accepted(late), isFalse);
      expectPayout(await call(znn.embedded.ptlc.reclaim(id)), self);
      await expectGone(id);
    });

    test('the node refuses what the validations refuse', () async {
      final t = await token();
      final expiration = (await frontier()).timestamp + 3600;
      final smallOrder = List<int>.filled(32, 0)..[0] = 1;
      expect(Validations.ptlcPointLock(ptlcPointTypeEd25519, smallOrder),
          isNotNull);
      await expectRefusedAtPublish(znn.embedded.ptlc.create(t, BigInt.one,
          expiration, ptlcPointTypeEd25519, smallOrder, emptyAddress));

      final point = Secp256k1.scalarToPoint(BigInt.from(12345));
      expect(
          Validations.ptlcDestination(
              ptlcPointTypeSecp256k1Point, emptyAddress),
          isNotNull);
      await expectRefusedAtPublish(znn.embedded.ptlc.create(t, BigInt.one,
          expiration, ptlcPointTypeSecp256k1Point, point, emptyAddress));

      expect(Validations.ptlcDestination(ptlcPointTypeSecp256k1Point, htlcAddress),
          isNotNull);
      await expectRefusedAtPublish(znn.embedded.ptlc.create(t, BigInt.one,
          expiration, ptlcPointTypeSecp256k1Point, point, htlcAddress));

      expect(Validations.ptlcPointLock(3, List.filled(32, 1)), isNotNull);
      await expectRefusedAtPublish(znn.embedded.ptlc.create(
          t, BigInt.one, expiration, 3, List.filled(32, 1), emptyAddress));

      await expectRefusedAtPublish(
          znn.embedded.ptlc.unlock(Hash.digest([1]), List.filled(40, 1)));
      await expectRefusedAtPublish(znn.embedded.ptlc
          .proxyUnlock(Hash.digest([1]), htlcAddress, List.filled(32, 1)));
    });
  },
      skip: skip,
      timeout: const Timeout(Duration(minutes: 5)));
}
