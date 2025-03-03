import 'package:crypto/crypto.dart' as crypto;

/// Digest auth hash algorithm with strength ordering for negotiation.
enum DigestAlgorithm {
  md5(headerValue: 'MD5', strength: 0),
  sha256(headerValue: 'SHA-256', strength: 1),

  /// Header value uses hyphen, not slash: "SHA-512-256".
  sha512_256(headerValue: 'SHA-512-256', strength: 2);

  final String headerValue;
  final int strength;

  const DigestAlgorithm({required this.headerValue, required this.strength});

  /// Hash [bytes] and return the hex digest.
  String hash(List<int> bytes) => switch (this) {
        DigestAlgorithm.md5 => crypto.md5.convert(bytes).toString(),
        DigestAlgorithm.sha256 => crypto.sha256.convert(bytes).toString(),
        DigestAlgorithm.sha512_256 =>
          crypto.sha512256.convert(bytes).toString(),
      };

  /// Case-insensitive lookup by header value. Returns null if unrecognized.
  static DigestAlgorithm? fromHeaderValue(String value) {
    final upper = value.toUpperCase();
    for (final algo in DigestAlgorithm.values) {
      if (algo.headerValue.toUpperCase() == upper) {
        return algo;
      }
    }
    return null;
  }

  /// Pick the strongest recognized algorithm. Falls back to MD5.
  static DigestAlgorithm selectStrongest(List<String> offered) {
    DigestAlgorithm best = DigestAlgorithm.md5;
    for (final value in offered) {
      final algo = fromHeaderValue(value);
      if (algo != null && algo.strength > best.strength) {
        best = algo;
      }
    }
    return best;
  }
}
