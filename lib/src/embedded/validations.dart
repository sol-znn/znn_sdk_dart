import 'package:znn_sdk_dart/src/crypto/ed25519_point.dart';
import 'package:znn_sdk_dart/src/crypto/secp256k1.dart';
import 'package:znn_sdk_dart/src/embedded/constants.dart';
import 'package:znn_sdk_dart/src/model/primitives.dart';

class Validations {
  static String? tokenName(String? value) {
    if (value != null) {
      if (value.isEmpty) {
        return 'Token name can\'t be empty';
      }
      if (!tokenNameRegExp.hasMatch(value)) {
        return 'Token name must contain only alphanumeric characters';
      }
      if (value.length > tokenNameMaxLength) {
        return 'Token name must have maximum $tokenNameMaxLength characters';
      }
      return null;
    } else {
      return 'Value is null';
    }
  }

  static String? tokenSymbol(String? value) {
    if (value != null) {
      if (value.isEmpty) {
        return 'Token symbol can\'t be empty';
      }
      if (!tokenSymbolRegExp.hasMatch(value)) {
        return 'Token symbol must match pattern: ${tokenSymbolRegExp.pattern}';
      }
      if (value.length > tokenSymbolMaxLength) {
        return 'Token symbol must have maximum $tokenSymbolMaxLength characters';
      }
      if (tokenSymbolExceptions.contains(value)) {
        return 'Token symbol must not be one of the following: ${tokenSymbolExceptions.join(', ')}';
      }
      return null;
    } else {
      return 'Value is null';
    }
  }

  static String? tokenDomain(String? value) {
    if (value != null) {
      if (value.isEmpty) {
        return 'Token domain can\'t be empty';
      }
      if (!tokenDomainRegExp.hasMatch(value)) {
        return 'Domain is not valid';
      }
      return null;
    } else {
      return 'Value is null';
    }
  }

  static String? pillarName(String? value) {
    if (value != null) {
      if (value.isEmpty) {
        return 'Pillar name can\'t be empty';
      }
      if (!pillarNameRegExp.hasMatch(value)) {
        return 'Pillar name must match pattern : ${pillarNameRegExp.pattern}';
      }
      if (value.length > pillarNameMaxLength) {
        return 'Pillar name must have maximum $pillarNameMaxLength characters';
      }
      return null;
    } else {
      return 'Value is null';
    }
  }

  static String? projectName(String? value) {
    if (value != null) {
      if (value.isEmpty) {
        return 'Project name can\'t be empty';
      }
      if (value.length > projectNameMaxLength) {
        return 'Project name must have maximum $projectNameMaxLength characters';
      }
      return null;
    } else {
      return 'Value is null';
    }
  }

  static String? projectDescription(String? value) {
    if (value != null) {
      if (value.isEmpty) {
        return 'Project description can\'t be empty';
      }
      if (value.length > projectDescriptionMaxLength) {
        return 'Project description must have maximum $projectDescriptionMaxLength characters';
      }
      return null;
    } else {
      return 'Value is null';
    }
  }

  static String? ptlcPointLock(int pointType, List<int>? value) {
    if (value != null) {
      final size = ptlcPointLockSizes[pointType];
      if (size == null) {
        return 'Point type $pointType is not supported';
      }
      if (value.length != size) {
        return 'Point lock must have $size bytes';
      }
      switch (pointType) {
        case ptlcPointTypeEd25519:
          if (!Ed25519Point.isValidLock(value)) {
            return 'Point lock is not a valid Ed25519 public key';
          }
          break;
        case ptlcPointTypeBip340:
          if (Secp256k1.liftX(value) == null) {
            return 'Point lock is not a valid BIP-340 public key';
          }
          break;
        case ptlcPointTypeSecp256k1Point:
          if (Secp256k1.parseCompressed(value) == null) {
            return 'Point lock is not a valid compressed secp256k1 point';
          }
          break;
      }
      return null;
    } else {
      return 'Value is null';
    }
  }

  static String? ptlcDestination(int pointType, Address? value) {
    if (value != null) {
      if (value == emptyAddress) {
        if (pointType == ptlcPointTypeSecp256k1Point) {
          return 'A secp256k1 point lock requires a destination';
        }
        return null;
      }
      if (value.core == null ||
          value.core!.isEmpty ||
          value.core![0] != Address.userByte) {
        return 'Destination must be a user address';
      }
      return null;
    } else {
      return 'Value is null';
    }
  }

  static String? ptlcReclaimLock(int pointType, List<int>? value) {
    if (value != null) {
      if (!ptlcReclaimPointTypes.contains(pointType)) {
        return 'Reclaim point type must be Ed25519 (0) or BIP-340 (1)';
      }
      return ptlcPointLock(pointType, value);
    } else {
      return 'Value is null';
    }
  }

  static String? ptlcReclaimSignature(List<int>? value) {
    if (value != null) {
      if (value.length != ptlcReclaimSignatureSize) {
        return 'Reclaim signature must have $ptlcReclaimSignatureSize bytes';
      }
      return null;
    } else {
      return 'Value is null';
    }
  }

  static String? ptlcWitness(int pointType, List<int>? value) {
    if (value != null) {
      final size = ptlcWitnessSizes[pointType];
      if (size == null) {
        return 'Point type $pointType is not supported';
      }
      if (value.length != size) {
        return 'Witness must have $size bytes';
      }
      return null;
    } else {
      return 'Value is null';
    }
  }
}
