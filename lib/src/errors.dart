/// Base exception for digest auth errors.
abstract class DigestAuthException implements Exception {
  final String message;
  const DigestAuthException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

/// Malformed or non-Digest WWW-Authenticate header.
class DigestAuthFormatException extends DigestAuthException {
  const DigestAuthFormatException(super.message);
}

/// Server indicated stale nonce. Nonce is already updated; retry immediately.
class StaleNonceException extends DigestAuthException {
  const StaleNonceException(super.message);
}

/// Credentials rejected (not a stale nonce).
class AuthenticationException extends DigestAuthException {
  const AuthenticationException(super.message);
}

/// Caller's explicit algorithm not offered by server.
class AlgorithmMismatchException extends DigestAuthException {
  const AlgorithmMismatchException(super.message);
}
