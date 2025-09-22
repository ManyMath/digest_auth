import 'package:crypto/crypto.dart' as crypto;

/// Digest auth hash algorithm with strength ordering for negotiation.
enum DigestAlgorithm {
  md5(headerValue: 'MD5', strength: 0, isSession: false),
  md5sess(headerValue: 'MD5-sess', strength: 0, isSession: true),
  sha256(headerValue: 'SHA-256', strength: 1, isSession: false),
  sha256sess(headerValue: 'SHA-256-sess', strength: 1, isSession: true),

  /// Header value uses hyphen, not slash: "SHA-512-256".
  sha512_256(headerValue: 'SHA-512-256', strength: 2, isSession: false),
  sha512_256sess(headerValue: 'SHA-512-256-sess', strength: 2, isSession: true);

  final String headerValue;
  final int strength;
  final bool isSession;

  const DigestAlgorithm({
    required this.headerValue,
    required this.strength,
    required this.isSession,
  });

  /// Non-session base algorithm for hash dispatch.
  DigestAlgorithm get baseAlgorithm => switch (this) {
        DigestAlgorithm.md5sess => DigestAlgorithm.md5,
        DigestAlgorithm.sha256sess => DigestAlgorithm.sha256,
        DigestAlgorithm.sha512_256sess => DigestAlgorithm.sha512_256,
        _ => this,
      };

  /// Hash [bytes] and return the hex digest.
  String hash(List<int> bytes) => switch (this) {
        DigestAlgorithm.md5 ||
        DigestAlgorithm.md5sess =>
          crypto.md5.convert(bytes).toString(),
        DigestAlgorithm.sha256 ||
        DigestAlgorithm.sha256sess =>
          crypto.sha256.convert(bytes).toString(),
        DigestAlgorithm.sha512_256 ||
        DigestAlgorithm.sha512_256sess =>
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
