import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:digest_auth/digest_auth.dart';
import 'package:test/test.dart';

void main() {
  group('DigestAlgorithm enum', () {
    test('md5 hash produces correct output', () {
      expect(
        DigestAlgorithm.md5.hash(utf8.encode('test')),
        equals('098f6bcd4621d373cade4e832627b4f6'),
      );
    });

    test('sha256 hash produces correct output', () {
      expect(
        DigestAlgorithm.sha256.hash(utf8.encode('test')),
        equals(crypto.sha256.convert(utf8.encode('test')).toString()),
      );
    });

    test('sha512_256 hash produces correct output', () {
      expect(
        DigestAlgorithm.sha512_256.hash(utf8.encode('test')),
        equals(crypto.sha512256.convert(utf8.encode('test')).toString()),
      );
    });

    test('md5 headerValue is MD5', () {
      expect(DigestAlgorithm.md5.headerValue, equals('MD5'));
    });

    test('sha256 headerValue is SHA-256', () {
      expect(DigestAlgorithm.sha256.headerValue, equals('SHA-256'));
    });

    test('sha512_256 headerValue is SHA-512-256', () {
      expect(DigestAlgorithm.sha512_256.headerValue, equals('SHA-512-256'));
    });

    test('fromHeaderValue is case insensitive', () {
      expect(DigestAlgorithm.fromHeaderValue('SHA-256'),
          equals(DigestAlgorithm.sha256));
      expect(DigestAlgorithm.fromHeaderValue('sha-256'),
          equals(DigestAlgorithm.sha256));
      expect(DigestAlgorithm.fromHeaderValue('Sha-256'),
          equals(DigestAlgorithm.sha256));
    });

    test('fromHeaderValue returns null for unknown', () {
      expect(DigestAlgorithm.fromHeaderValue('UNKNOWN'), isNull);
    });

    test('selectStrongest picks sha256 over md5', () {
      expect(
        DigestAlgorithm.selectStrongest(['MD5', 'SHA-256']),
        equals(DigestAlgorithm.sha256),
      );
    });

    test('selectStrongest picks sha512_256 over all', () {
      expect(
        DigestAlgorithm.selectStrongest(['SHA-512-256', 'MD5', 'SHA-256']),
        equals(DigestAlgorithm.sha512_256),
      );
    });

    test('selectStrongest defaults to md5 for unknown', () {
      expect(
        DigestAlgorithm.selectStrongest(['UNKNOWN']),
        equals(DigestAlgorithm.md5),
      );
    });

    test('strength ordering is correct', () {
      expect(DigestAlgorithm.sha512_256.strength,
          greaterThan(DigestAlgorithm.sha256.strength));
      expect(DigestAlgorithm.sha256.strength,
          greaterThan(DigestAlgorithm.md5.strength));
    });
  });

  group('AlgorithmMismatchException', () {
    test('extends DigestAuthException', () {
      final e = AlgorithmMismatchException('test message');
      expect(e, isA<DigestAuthException>());
      expect(e.message, equals('test message'));
    });
  });

  group('DigestAuth with algorithms', () {
    test('default constructor produces header with algorithm=MD5', () {
      final auth = DigestAuth(username: 'u', password: 'p');
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = auth.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=MD5'));
    });

    test('sha256 constructor produces header with algorithm=SHA-256', () {
      final auth = DigestAuth(
          username: 'u', password: 'p', algorithm: DigestAlgorithm.sha256);
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = auth.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test('sha512_256 constructor produces header with algorithm=SHA-512-256',
        () {
      final auth = DigestAuth(
          username: 'u', password: 'p', algorithm: DigestAlgorithm.sha512_256);
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = auth.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-512-256'));
    });

    test('default constructor backward compatible', () {
      final auth = DigestAuth(username: 'testuser', password: 'testpass');
      auth.initFromAuthorizationHeader(
        'Digest realm="monero-rpc",nonce="testnonce",qop="auth"',
      );
      final header =
          auth.buildAuthorizationHeader(method: 'POST', uri: '/json_rpc');
      expect(header, startsWith('Digest '));
      expect(header, contains('username="testuser"'));
      expect(header, contains('realm="monero-rpc"'));
      expect(header, contains('response="'));
    });
  });

  group('RFC 7616 S3.9.1 test vectors', () {
    String computeResponse(
        DigestAlgorithm algo,
        String username,
        String password,
        String realm,
        String nonce,
        String nc,
        String cnonce,
        String qop,
        String method,
        String uri) {
      final ha1 = algo.hash(utf8.encode('$username:$realm:$password'));
      final ha2 = algo.hash(utf8.encode('$method:$uri'));
      return algo.hash(utf8.encode('$ha1:$nonce:$nc:$cnonce:$qop:$ha2'));
    }

    const username = 'Mufasa';
    const password = 'Circle of Life';
    const realm = 'http-auth@example.org';
    const nonce = '7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v';
    const cnonce = 'f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ';
    const nc = '00000001';
    const qop = 'auth';
    const method = 'GET';
    const uri = '/dir/index.html';

    test('MD5 vector matches RFC 7616 S3.9.1', () {
      final response = computeResponse(DigestAlgorithm.md5, username, password,
          realm, nonce, nc, cnonce, qop, method, uri);
      expect(response, equals('8ca523f5e9506fed4657c9700eebdbec'));
    });

    test('SHA-256 vector matches RFC 7616 S3.9.1', () {
      final response = computeResponse(DigestAlgorithm.sha256, username,
          password, realm, nonce, nc, cnonce, qop, method, uri);
      expect(
          response,
          equals(
              '753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1'));
    });

    test('SHA-512/256 primitive: NIST FIPS 180-4 vector', () {
      // SHA-512/256("abc") from NIST test vectors
      expect(
        DigestAlgorithm.sha512_256.hash(utf8.encode('abc')),
        equals(
            '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23'),
      );
    });

    test('SHA-512/256 digest auth vector (independently computed)', () {
      final response = computeResponse(DigestAlgorithm.sha512_256, username,
          password, realm, nonce, nc, cnonce, qop, method, uri);
      // Compute expected values independently
      final ha1 = DigestAlgorithm.sha512_256
          .hash(utf8.encode('$username:$realm:$password'));
      final ha2 = DigestAlgorithm.sha512_256.hash(utf8.encode('$method:$uri'));
      final expected = DigestAlgorithm.sha512_256
          .hash(utf8.encode('$ha1:$nonce:$nc:$cnonce:$qop:$ha2'));
      expect(response, equals(expected));
    });
  });
}
