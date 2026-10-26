import 'package:znn_sdk_dart/src/model/primitives.dart';
import 'package:znn_sdk_dart/src/utils/utils.dart';

class PtlcInfo {
  Hash id;
  Address timeLocked;
  TokenStandard tokenStandard;
  BigInt amount;
  int expirationTime;
  int pointType;
  List<int> pointLock;
  Address destination;

  PtlcInfo(
      {required this.id,
      required this.timeLocked,
      required this.tokenStandard,
      required this.amount,
      required this.expirationTime,
      required this.pointType,
      required this.pointLock,
      required this.destination});

  PtlcInfo.fromJson(Map<String, dynamic> json)
      : id = Hash.parse(json['id']),
        timeLocked = Address.parse(json['timeLocked']),
        tokenStandard = TokenStandard.parse(json['tokenStandard']),
        amount = BigInt.parse(json['amount'].toString()),
        expirationTime = json['expirationTime'],
        pointType = json['pointType'],
        pointLock = BytesUtils.base64ToBytes(json['pointLock'] ?? '') ?? [],
        destination = Address.parse(json['destination']);

  bool get hasFixedDestination => destination != emptyAddress;

  Map<String, dynamic> toJson() => {
        'id': id.toString(),
        'timeLocked': timeLocked.toString(),
        'tokenStandard': tokenStandard.toString(),
        'amount': amount.toString(),
        'expirationTime': expirationTime,
        'pointType': pointType,
        'pointLock': BytesUtils.bytesToBase64(pointLock),
        'destination': destination.toString()
      };
}

class PtlcReclaimLock {
  Hash id;
  int pointType;
  List<int> pointLock;

  PtlcReclaimLock(
      {required this.id, required this.pointType, required this.pointLock});

  PtlcReclaimLock.fromJson(Map<String, dynamic> json)
      : id = Hash.parse(json['id']),
        pointType = json['pointType'],
        pointLock = BytesUtils.base64ToBytes(json['pointLock'] ?? '') ?? [];

  Map<String, dynamic> toJson() => {
        'id': id.toString(),
        'pointType': pointType,
        'pointLock': BytesUtils.bytesToBase64(pointLock)
      };
}
