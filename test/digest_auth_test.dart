import 'package:digest_auth/digest_auth.dart';
import 'package:test/test.dart';

void main() {
  group('DigestAuth', () {
    test('constructor creates instance', () {
      final auth = DigestAuth('user', 'pass');
      expect(auth.username, equals('user'));
      expect(auth.password, equals('pass'));
    });
  });

  group('Error types', () {
    test('DigestAuthFormatException is a DigestAuthException', () {
      const e = DigestAuthFormatException('bad header');
      expect(e, isA<DigestAuthException>());
      expect(e.message, equals('bad header'));
      expect(e.toString(), contains('DigestAuthFormatException'));
    });

    test('StaleNonceException is a DigestAuthException', () {
      const e = StaleNonceException('stale');
      expect(e, isA<DigestAuthException>());
      expect(e.message, equals('stale'));
    });

    test('AuthenticationException is a DigestAuthException', () {
      const e = AuthenticationException('auth failed');
      expect(e, isA<DigestAuthException>());
      expect(e.message, equals('auth failed'));
    });
  });
}
