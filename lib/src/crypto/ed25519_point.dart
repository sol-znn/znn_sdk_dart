class Ed25519Point {
  static final BigInt _p = (BigInt.one << 255) - BigInt.from(19);
  static final BigInt _d =
      (BigInt.from(-121665) * BigInt.from(121666).modInverse(_p)) % _p;
  static final BigInt _sqrtM1 =
      BigInt.two.modPow((_p - BigInt.one) ~/ BigInt.from(4), _p);

  static List<BigInt>? decode(List<int> bytes) {
    if (bytes.length != 32) return null;
    final sign = bytes[31] >> 7;
    var y = BigInt.zero;
    for (var i = 31; i >= 0; i--) {
      y = (y << 8) | BigInt.from(i == 31 ? bytes[i] & 0x7f : bytes[i]);
    }
    y = y % _p;
    final y2 = y * y % _p;
    final u = (y2 - BigInt.one) % _p;
    final v = (_d * y2 + BigInt.one) % _p;
    final v3 = v.modPow(BigInt.from(3), _p);
    final v7 = v.modPow(BigInt.from(7), _p);
    var x = u *
        v3 %
        _p *
        (u * v7 % _p).modPow((_p - BigInt.from(5)) ~/ BigInt.from(8), _p) %
        _p;
    final vx2 = v * x % _p * x % _p;
    if (vx2 != u) {
      if (vx2 == (_p - u) % _p) {
        x = x * _sqrtM1 % _p;
      } else {
        return null;
      }
    }
    if (sign == 1) x = (_p - x) % _p;
    return [x, y];
  }

  static bool isCanonical(List<int> bytes) {
    if (bytes.length != 32) return false;
    var y = BigInt.zero;
    for (var i = 31; i >= 0; i--) {
      y = (y << 8) | BigInt.from(i == 31 ? bytes[i] & 0x7f : bytes[i]);
    }
    if (y >= _p) return false;
    final point = decode(bytes);
    if (point == null) return false;
    return !(point[0] == BigInt.zero && bytes[31] >> 7 == 1);
  }

  static bool hasSmallOrder(List<BigInt> point) {
    var x = point[0], y = point[1], z = BigInt.one;
    for (var i = 0; i < 3; i++) {
      final a = x * x % _p;
      final b = y * y % _p;
      final c = BigInt.two * z * z % _p;
      final h = (a + b) % _p;
      final e = (h - (x + y) * (x + y)) % _p;
      final g = (a - b) % _p;
      final f = (c + g) % _p;
      x = e * f % _p;
      y = g * h % _p;
      z = f * g % _p;
    }
    return x == BigInt.zero && y == z;
  }

  static bool isValidLock(List<int> bytes) {
    final point = decode(bytes);
    return point != null && !hasSmallOrder(point);
  }
}
