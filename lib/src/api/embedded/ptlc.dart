import 'dart:typed_data';

import 'package:collection/collection.dart';
import 'package:znn_sdk_dart/src/client/client.dart';
import 'package:znn_sdk_dart/src/crypto/crypto.dart';
import 'package:znn_sdk_dart/src/crypto/ed25519.dart' as ed25519;
import 'package:znn_sdk_dart/src/embedded/embedded.dart';
import 'package:znn_sdk_dart/src/model/model.dart';
import 'package:znn_sdk_dart/src/model/primitives.dart';

class PtlcApi {
  late Client client;

  void setClient(Client client) {
    this.client = client;
  }

  Future<PtlcInfo> getById(Hash id) async {
    var response =
        await client.sendRequest('embedded.ptlc.getById', [id.toString()]);
    return PtlcInfo.fromJson(response!);
  }

  Future<PtlcReclaimLock> getReclaimLockById(Hash id) async {
    var response = await client
        .sendRequest('embedded.ptlc.getReclaimLockById', [id.toString()]);
    return PtlcReclaimLock.fromJson(response!);
  }

  AccountBlockTemplate createWithReclaimLock(
      Token token,
      BigInt amount,
      int expirationTime,
      int pointType,
      List<int> pointLock,
      Address destination,
      int reclaimPointType,
      List<int> reclaimPointLock) {
    return AccountBlockTemplate.callContract(
        ptlcAddress,
        token.tokenStandard,
        amount,
        Definitions.ptlc.encodeFunction('CreateWithReclaimLock', [
          expirationTime,
          pointType,
          pointLock,
          destination,
          reclaimPointType,
          reclaimPointLock
        ]));
  }

  AccountBlockTemplate reclaimWithSignature(Hash id, List<int> signature) {
    return AccountBlockTemplate.callContract(
        ptlcAddress,
        znnZts,
        BigInt.zero,
        Definitions.ptlc.encodeFunction(
            'ReclaimWithSignature', [id.getBytes(), signature]));
  }

  AccountBlockTemplate create(Token token, BigInt amount, int expirationTime,
      int pointType, List<int> pointLock, Address destination) {
    return AccountBlockTemplate.callContract(
        ptlcAddress,
        token.tokenStandard,
        amount,
        Definitions.ptlc.encodeFunction(
            'Create', [expirationTime, pointType, pointLock, destination]));
  }

  AccountBlockTemplate reclaim(Hash id) {
    return AccountBlockTemplate.callContract(ptlcAddress, znnZts, BigInt.zero,
        Definitions.ptlc.encodeFunction('Reclaim', [id.getBytes()]));
  }

  AccountBlockTemplate unlock(Hash id, List<int> signature) {
    return AccountBlockTemplate.callContract(ptlcAddress, znnZts, BigInt.zero,
        Definitions.ptlc.encodeFunction('Unlock', [id.getBytes(), signature]));
  }

  AccountBlockTemplate proxyUnlock(
      Hash id, Address destination, List<int> signature) {
    return AccountBlockTemplate.callContract(
        ptlcAddress,
        znnZts,
        BigInt.zero,
        Definitions.ptlc.encodeFunction(
            'ProxyUnlock', [id.getBytes(), destination, signature]));
  }

  static List<int> unlockMessage(
      int chainIdentifier, int pointType, Hash id, Address destination) {
    final chain = Uint8List(8);
    ByteData.view(chain.buffer).setUint64(0, chainIdentifier, Endian.big);
    return Crypto.digest([
      ...ptlcUnlockMessageDomain.codeUnits,
      ...chain,
      ...ptlcAddress.getBytes()!,
      pointType,
      ...id.getBytes()!,
      ...destination.getBytes()!,
    ]);
  }

  static Future<bool> verifyWitness(
      int chainIdentifier,
      int pointType,
      List<int> pointLock,
      Hash id,
      Address destination,
      List<int> witness) async {
    final witnessSize = ptlcWitnessSizes[pointType];
    if (witnessSize == null || witness.length != witnessSize) {
      return false;
    }
    switch (pointType) {
      case ptlcPointTypeEd25519:
        return _verifyEd25519(
            pointLock,
            unlockMessage(chainIdentifier, pointType, id, destination),
            witness);
      case ptlcPointTypeBip340:
        return Bip340.verify(
            pointLock,
            unlockMessage(chainIdentifier, pointType, id, destination),
            witness);
      case ptlcPointTypeSecp256k1Point:
        final scalar = Secp256k1.parseScalar(witness);
        return scalar != null &&
            const ListEquality<int>()
                .equals(Secp256k1.scalarToPoint(scalar), pointLock);
    }
    return false;
  }

  static List<int> reclaimMessage(
      int chainIdentifier,
      int reclaimPointType,
      Address timeLocked,
      Address destination,
      TokenStandard tokenStandard,
      BigInt amount,
      int expirationTime,
      int pointType,
      List<int> pointLock) {
    final chain = Uint8List(8);
    ByteData.view(chain.buffer).setUint64(0, chainIdentifier, Endian.big);
    final expiration = Uint8List(8);
    ByteData.view(expiration.buffer).setInt64(0, expirationTime, Endian.big);
    return Crypto.digest([
      ...ptlcReclaimMessageDomain.codeUnits,
      ...chain,
      ...ptlcAddress.getBytes()!,
      reclaimPointType,
      ...timeLocked.getBytes()!,
      ...destination.getBytes()!,
      ...tokenStandard.getBytes(),
      ...Secp256k1.bigIntToBytes(amount, 32),
      ...expiration,
      pointType,
      ...pointLock,
    ]);
  }

  static List<int> reclaimMessageOf(
      int chainIdentifier, int reclaimPointType, PtlcInfo entry) {
    return reclaimMessage(
        chainIdentifier,
        reclaimPointType,
        entry.timeLocked,
        entry.destination,
        entry.tokenStandard,
        entry.amount,
        entry.expirationTime,
        entry.pointType,
        entry.pointLock);
  }

  static Future<bool> verifyReclaimSignature(
      int chainIdentifier,
      PtlcInfo entry,
      int reclaimPointType,
      List<int> reclaimPointLock,
      List<int> signature) async {
    if (Validations.ptlcReclaimLock(reclaimPointType, reclaimPointLock) !=
        null) {
      return false;
    }
    if (Validations.ptlcReclaimSignature(signature) != null) {
      return false;
    }
    final message = reclaimMessageOf(chainIdentifier, reclaimPointType, entry);
    switch (reclaimPointType) {
      case ptlcPointTypeEd25519:
        return _verifyEd25519(reclaimPointLock, message, signature);
      case ptlcPointTypeBip340:
        return Bip340.verify(reclaimPointLock, message, signature);
    }
    return false;
  }

  static Future<bool> _verifyEd25519(
      List<int> pointLock, List<int> message, List<int> signature) async {
    if (pointLock.length != 32) return false;
    if (!Ed25519Point.isCanonical(signature.sublist(0, 32))) return false;
    var s = BigInt.zero;
    for (var i = 63; i >= 32; i--) {
      s = (s << 8) | BigInt.from(signature[i]);
    }
    if (s >= ed25519.Ed25519.l) return false;
    try {
      return await Crypto.verify(Uint8List.fromList(signature),
          Uint8List.fromList(message), Uint8List.fromList(pointLock));
    } catch (_) {
      return false;
    }
  }
}
