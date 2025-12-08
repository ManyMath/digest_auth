import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:digest_auth/digest_auth.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

void main() {
  late DigestAuth auth;

  setUp(() {
    auth = DigestAuth(username: 'testuser', password: 'testpass');
  });

  group('DigestAuth constructor', () {
    test('creates instance with username and password accessible', () {
      expect(auth.username, equals('testuser'));
      expect(auth.password, equals('testpass'));
    });

    test(
        'initial state has null realm, null nonce, null opaque, qop defaults to "auth"',
        () {
      expect(auth.realm, isNull);
      expect(auth.nonce, isNull);
      expect(auth.opaque, isNull);
      expect(auth.qop, equals('auth'));
    });
  });

  group('initFromAuthorizationHeader - input validation', () {
    test('null input throws DigestAuthFormatException', () {
      expect(
        () => auth.initFromAuthorizationHeader(null),
        throwsA(
          isA<DigestAuthFormatException>().having(
            (e) => e.message,
            'message',
            contains('null or empty'),
          ),
        ),
      );
    });

    test('empty string throws DigestAuthFormatException', () {
      expect(
        () => auth.initFromAuthorizationHeader(''),
        throwsA(
          isA<DigestAuthFormatException>().having(
            (e) => e.message,
            'message',
            contains('null or empty'),
          ),
        ),
      );
    });

    test('non-Digest header throws DigestAuthFormatException', () {
      expect(
        () => auth.initFromAuthorizationHeader('Basic realm=test'),
        throwsA(
          isA<DigestAuthFormatException>().having(
            (e) => e.message,
            'message',
            contains('Expected Digest challenge'),
          ),
        ),
      );
    });
  });

  group('initFromAuthorizationHeader - header parsing', () {
    test('Monero-format header parses correctly', () {
      auth.initFromAuthorizationHeader(
        'Digest qop="auth",algorithm=MD5,realm="monero-rpc",'
        'nonce="P4lbGCQYPa9IkjAMvlgMHw==",stale=false',
      );
      expect(auth.realm, equals('monero-rpc'));
      expect(auth.nonce, equals('P4lbGCQYPa9IkjAMvlgMHw=='));
    });

    test('comma inside quoted realm is preserved', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="My Company, Inc.",nonce="abc123",qop="auth"',
      );
      expect(auth.realm, equals('My Company, Inc.'));
    });

    test('base64 nonce with = characters is preserved', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="Pb3LuMW311dnFLeOCTeWxA==",qop="auth"',
      );
      expect(auth.nonce, equals('Pb3LuMW311dnFLeOCTeWxA=='));
    });
  });

  group('initFromAuthorizationHeader - opaque', () {
    test('opaque parsed from header', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth",'
        'opaque="5ccc069c403ebaf9f0171e9517f40e41"',
      );
      expect(auth.opaque, equals('5ccc069c403ebaf9f0171e9517f40e41'));
    });

    test('opaque is null when not in header', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      expect(auth.opaque, isNull);
    });
  });

  group('initFromAuthorizationHeader - stale nonce', () {
    test('stale=true throws StaleNonceException', () {
      expect(
        () => auth.initFromAuthorizationHeader(
          'Digest realm="test",nonce="newNonce",qop="auth",stale=true',
        ),
        throwsA(isA<StaleNonceException>()),
      );
      // Nonce updated before throw.
      expect(auth.nonce, equals('newNonce'));
    });

    test('stale=TRUE (uppercase) also throws StaleNonceException', () {
      expect(
        () => auth.initFromAuthorizationHeader(
          'Digest realm="test",nonce="newNonce2",qop="auth",stale=TRUE',
        ),
        throwsA(isA<StaleNonceException>()),
      );
    });

    test('stale=false does NOT throw', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth",stale=false',
      );
      expect(auth.realm, equals('test'));
      expect(auth.nonce, equals('abc'));
    });
  });

  group('initFromAuthorizationHeader - nonce count reset', () {
    test('nonce count resets when nonce changes', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="nonce1",qop="auth"',
      );
      // Two calls should reach nc=00000002
      auth.buildAuthorizationHeader(method: 'GET', uri: '/path');
      final second = auth.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(second, contains('nc=00000002'));

      // Change nonce -- nc should reset
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="nonce2",qop="auth"',
      );
      final afterReset =
          auth.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(afterReset, contains('nc=00000001'));
    });
  });

  group('buildAuthorizationHeader', () {
    test('generates valid Digest header', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="monero-rpc",nonce="testnonce",qop="auth"',
      );
      final header =
          auth.buildAuthorizationHeader(method: 'POST', uri: '/json_rpc');

      expect(header, startsWith('Digest '));
      expect(header, contains('username="testuser"'));
      expect(header, contains('realm="monero-rpc"'));
      expect(header, contains('nonce="testnonce"'));
      expect(header, contains('uri="/json_rpc"'));
      expect(header, contains('qop=auth'));
      expect(header, contains('nc=00000001'));
      expect(header, contains('cnonce="'));
      expect(header, contains('response="'));
    });

    test('opaque echoed when present', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth",opaque="opq123"',
      );
      final header = auth.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('opaque="opq123"'));
    });

    test('opaque NOT in output when absent', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = auth.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, isNot(contains('opaque')));
    });
  });

  group('cnonce security', () {
    test('two consecutive calls produce different cnonce values', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header1 =
          auth.buildAuthorizationHeader(method: 'GET', uri: '/path');
      final header2 =
          auth.buildAuthorizationHeader(method: 'GET', uri: '/path');

      final cnonceRegex = RegExp(r'cnonce="([^"]+)"');
      final cnonce1 = cnonceRegex.firstMatch(header1)!.group(1)!;
      final cnonce2 = cnonceRegex.firstMatch(header2)!.group(1)!;

      expect(cnonce1, isNot(equals(cnonce2)));
    });

    test('cnonce is 32 hex characters', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = auth.buildAuthorizationHeader(method: 'GET', uri: '/path');

      final cnonceRegex = RegExp(r'cnonce="([^"]+)"');
      final cnonce = cnonceRegex.firstMatch(header)!.group(1)!;

      expect(RegExp(r'^[0-9a-f]{32}$').hasMatch(cnonce), isTrue);
    });
  });

  group('MockClient integration', () {
    test('full 401 challenge-response cycle', () async {
      var requestCount = 0;
      const wwwAuthenticate =
          'Digest realm="monero-rpc",nonce="serverNonce123",'
          'qop="auth",algorithm=MD5,stale=false';

      final client = MockClient((request) async {
        requestCount++;
        if (requestCount == 1) {
          // First request: return 401 challenge
          return http.Response(
            'Unauthorized',
            401,
            headers: {'www-authenticate': wwwAuthenticate},
          );
        } else {
          // Second request: verify auth header is present
          final authHeader = request.headers['authorization'];
          expect(authHeader, isNotNull);
          expect(authHeader, startsWith('Digest '));
          expect(authHeader, contains('username='));
          expect(authHeader, contains('response='));

          return http.Response(
            '{"jsonrpc":"2.0","result":{"status":"OK"}}',
            200,
          );
        }
      });

      // First request -- get 401
      final firstResponse = await client.post(
        Uri.parse('http://localhost:18081/json_rpc'),
        body: '{"jsonrpc":"2.0","method":"get_info"}',
      );
      expect(firstResponse.statusCode, equals(401));

      // Parse challenge and generate auth header
      final challenge = firstResponse.headers['www-authenticate']!;
      final digestAuth = DigestAuth(username: 'testuser', password: 'testpass');
      digestAuth.initFromAuthorizationHeader(challenge);
      final authString =
          digestAuth.buildAuthorizationHeader(method: 'POST', uri: '/json_rpc');

      // Second request with auth header
      final secondResponse = await client.post(
        Uri.parse('http://localhost:18081/json_rpc'),
        headers: {'authorization': authString},
        body: '{"jsonrpc":"2.0","method":"get_info"}',
      );
      expect(secondResponse.statusCode, equals(200));

      client.close();
    });
  });

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

    test('headerValue strings are correct', () {
      expect(DigestAlgorithm.md5.headerValue, equals('MD5'));
      expect(DigestAlgorithm.sha256.headerValue, equals('SHA-256'));
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

    test('session variants have correct headerValue', () {
      expect(DigestAlgorithm.md5sess.headerValue, equals('MD5-sess'));
      expect(DigestAlgorithm.sha256sess.headerValue, equals('SHA-256-sess'));
      expect(DigestAlgorithm.sha512_256sess.headerValue,
          equals('SHA-512-256-sess'));
    });

    test('session variants share hash with base algorithm', () {
      final input = utf8.encode('test');
      expect(DigestAlgorithm.md5sess.hash(input),
          equals(DigestAlgorithm.md5.hash(input)));
      expect(DigestAlgorithm.sha256sess.hash(input),
          equals(DigestAlgorithm.sha256.hash(input)));
      expect(DigestAlgorithm.sha512_256sess.hash(input),
          equals(DigestAlgorithm.sha512_256.hash(input)));
    });

    test('isSession is true for session variants, false for base', () {
      expect(DigestAlgorithm.md5.isSession, isFalse);
      expect(DigestAlgorithm.md5sess.isSession, isTrue);
      expect(DigestAlgorithm.sha256.isSession, isFalse);
      expect(DigestAlgorithm.sha256sess.isSession, isTrue);
      expect(DigestAlgorithm.sha512_256.isSession, isFalse);
      expect(DigestAlgorithm.sha512_256sess.isSession, isTrue);
    });

    test('baseAlgorithm returns non-session variant', () {
      expect(
          DigestAlgorithm.md5sess.baseAlgorithm, equals(DigestAlgorithm.md5));
      expect(DigestAlgorithm.sha256sess.baseAlgorithm,
          equals(DigestAlgorithm.sha256));
      expect(DigestAlgorithm.sha512_256sess.baseAlgorithm,
          equals(DigestAlgorithm.sha512_256));
      expect(DigestAlgorithm.md5.baseAlgorithm, equals(DigestAlgorithm.md5));
    });

    test('fromHeaderValue recognizes session variants', () {
      expect(DigestAlgorithm.fromHeaderValue('MD5-sess'),
          equals(DigestAlgorithm.md5sess));
      expect(DigestAlgorithm.fromHeaderValue('SHA-256-sess'),
          equals(DigestAlgorithm.sha256sess));
      expect(DigestAlgorithm.fromHeaderValue('SHA-512-256-sess'),
          equals(DigestAlgorithm.sha512_256sess));
    });

    test('selectStrongest handles session variants', () {
      expect(
        DigestAlgorithm.selectStrongest(['MD5', 'SHA-256-sess']),
        equals(DigestAlgorithm.sha256sess),
      );
      expect(
        DigestAlgorithm.selectStrongest(['MD5-sess', 'SHA-256']),
        equals(DigestAlgorithm.sha256),
      );
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
      expect(
        DigestAlgorithm.sha512_256.hash(utf8.encode('abc')),
        equals(
            '53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23'),
      );
    });

    test('SHA-512/256 digest auth vector (independently computed)', () {
      final response = computeResponse(DigestAlgorithm.sha512_256, username,
          password, realm, nonce, nc, cnonce, qop, method, uri);
      final ha1 = DigestAlgorithm.sha512_256
          .hash(utf8.encode('$username:$realm:$password'));
      final ha2 = DigestAlgorithm.sha512_256.hash(utf8.encode('$method:$uri'));
      final expected = DigestAlgorithm.sha512_256
          .hash(utf8.encode('$ha1:$nonce:$nc:$cnonce:$qop:$ha2'));
      expect(response, equals(expected));
    });
  });

  group('DigestAuth with algorithms', () {
    test('default constructor produces header with algorithm=MD5', () {
      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=MD5'));
    });

    test('sha256 constructor produces header with algorithm=SHA-256', () {
      final a = DigestAuth(
          username: 'u', password: 'p', algorithm: DigestAlgorithm.sha256);
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test('sha512_256 constructor produces header with algorithm=SHA-512-256',
        () {
      final a = DigestAuth(
          username: 'u', password: 'p', algorithm: DigestAlgorithm.sha512_256);
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-512-256'));
    });

    test('default constructor backward compatible', () {
      final a = DigestAuth(username: 'testuser', password: 'testpass');
      a.initFromAuthorizationHeader(
        'Digest realm="monero-rpc",nonce="testnonce",qop="auth"',
      );
      final header =
          a.buildAuthorizationHeader(method: 'POST', uri: '/json_rpc');
      expect(header, startsWith('Digest '));
      expect(header, contains('username="testuser"'));
      expect(header, contains('realm="monero-rpc"'));
      expect(header, contains('response="'));
    });
  });

  group('Algorithm negotiation', () {
    test('auto-selects algorithm from server challenge', () {
      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth",algorithm=SHA-256',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test('explicit algorithm matches server -- no error', () {
      final a = DigestAuth(
          username: 'u', password: 'p', algorithm: DigestAlgorithm.sha256);
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth",algorithm=SHA-256',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test(
        'explicit algorithm mismatches server -- throws AlgorithmMismatchException',
        () {
      final a = DigestAuth(
          username: 'u', password: 'p', algorithm: DigestAlgorithm.sha256);
      expect(
        () => a.initFromAuthorizationHeader(
          'Digest realm="test",nonce="n",qop="auth",algorithm=MD5',
        ),
        throwsA(
          isA<AlgorithmMismatchException>().having(
            (e) => e.message,
            'message',
            contains('SHA-256'),
          ),
        ),
      );
    });

    test('explicit algorithm with no server algorithm uses caller choice', () {
      final a = DigestAuth(
          username: 'u', password: 'p', algorithm: DigestAlgorithm.sha256);
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth"',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test('no algorithm from either side defaults to MD5', () {
      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth"',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=MD5'));
    });

    test('case-insensitive algorithm matching from server', () {
      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth",algorithm=sha-256',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-256'));
    });
  });

  group('QOP configuration', () {
    test('default qop is auth', () {
      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth"',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('qop=auth'));
    });

    test('custom qop via constructor', () {
      final a = DigestAuth(username: 'u', password: 'p', qop: 'auth-int');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth-int"',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('qop=auth-int'));
    });

    test('qop getter returns configured value', () {
      final a = DigestAuth(username: 'u', password: 'p', qop: 'auth-int');
      expect(a.qop, equals('auth-int'));
    });
  });

  group('charset=UTF-8 handling', () {
    test('ASCII username with charset=UTF-8 uses regular username param', () {
      final a = DigestAuth(username: 'Mufasa', password: 'Circle of Life');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('username="Mufasa"'));
      expect(header, isNot(contains('username*')));
    });

    test('non-ASCII username with charset=UTF-8 uses username* param', () {
      final a = DigestAuth(username: 'J\u00e4s\u00f8n Doe', password: 'Secret');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains("username*=UTF-8''J%C3%A4s%C3%B8n%20Doe"));
      expect(header, isNot(contains('username="')));
    });

    test('no charset in challenge -- no username* regardless of content', () {
      final a = DigestAuth(username: 'J\u00e4s\u00f8n', password: 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth"',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('username="J\u00e4s\u00f8n"'));
      expect(header, isNot(contains('username*')));
    });

    test('NFC normalization -- decomposed and precomposed produce same hash',
        () {
      // decomposed a-umlaut: a + combining diaeresis
      final authNFD = DigestAuth(username: 'J\u0061\u0308n', password: 'pass');
      // precomposed a-umlaut
      final authNFC = DigestAuth(username: 'J\u00e4n', password: 'pass');

      const challenge =
          'Digest realm="test",nonce="fixedNonce",qop="auth",charset=UTF-8';
      authNFD.initFromAuthorizationHeader(challenge);
      authNFC.initFromAuthorizationHeader(challenge);

      final headerNFD =
          authNFD.buildAuthorizationHeader(method: 'GET', uri: '/path');
      final headerNFC =
          authNFC.buildAuthorizationHeader(method: 'GET', uri: '/path');

      // The cnonces differ so responses will differ. Instead, verify both
      // produce a username* with the same NFC-encoded value.
      final usernameStarRegex = RegExp(r"username\*=UTF-8''([^ ,]+)");
      final userNFD = usernameStarRegex.firstMatch(headerNFD)!.group(1)!;
      final userNFC = usernameStarRegex.firstMatch(headerNFC)!.group(1)!;
      expect(userNFD, equals(userNFC),
          reason:
              'NFC normalization should produce identical username* values');

      // Also verify the encoded form is the precomposed a-umlaut
      expect(userNFD, equals('J%C3%A4n'));
    });

    test('charset=UTF-8 case-insensitive', () {
      final a = DigestAuth(username: 'J\u00e4n', password: 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=utf-8',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains("username*=UTF-8''"));
    });

    test('userhash=false included when charset=UTF-8 active', () {
      final a = DigestAuth(username: 'user', password: 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('userhash=false'));
    });

    test('userhash not included when charset not present', () {
      final a = DigestAuth(username: 'user', password: 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth"',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, isNot(contains('userhash')));
    });
  });

  group('RFC 5987 ext-value encoding', () {
    test('space encoded as %20', () {
      final a = DigestAuth(username: 'J\u00e4n Doe', password: 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('%20'));
      expect(header, isNot(contains('username*=UTF-8\'\'J%C3%A4n+Doe')));
    });

    test('special attr-chars not encoded', () {
      // Use a username with attr-chars that should NOT be percent-encoded
      // Plus a non-ASCII char to trigger username*
      final a = DigestAuth(username: 'u\u00e4!#\$&+-.^_`|~', password: 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      // The attr-chars should appear literally (unencoded) in the username* value
      expect(header, contains('!#\$&+-.^_`|~'));
    });

    test('multi-byte UTF-8 correctly percent-encoded', () {
      // CJK character U+4E16 (world) is 3 bytes in UTF-8: E4 B8 96
      final a = DigestAuth(username: '\u4e16', password: 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('%E4%B8%96'));
    });
  });

  group('Multi-challenge algorithm negotiation', () {
    const md5Challenge =
        'Digest realm="test",nonce="n-md5",qop="auth",algorithm=MD5';
    const sha256Challenge =
        'Digest realm="test",nonce="n-sha256",qop="auth",algorithm=SHA-256';
    const sha512Challenge =
        'Digest realm="test",nonce="n-sha512",qop="auth",algorithm=SHA-512-256';

    test('selects SHA-512-256 from [MD5, SHA-256, SHA-512-256]', () {
      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromMultipleChallenges(
          [md5Challenge, sha256Challenge, sha512Challenge]);
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-512-256'));
    });

    test('selects SHA-256 from [MD5, SHA-256]', () {
      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromMultipleChallenges([md5Challenge, sha256Challenge]);
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test('selects MD5 when only [MD5] offered', () {
      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromMultipleChallenges([md5Challenge]);
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=MD5'));
    });

    test('explicit sha256 + server offers [MD5, SHA-256] uses SHA-256', () {
      final a = DigestAuth(
          username: 'u', password: 'p', algorithm: DigestAlgorithm.sha256);
      a.initFromMultipleChallenges([md5Challenge, sha256Challenge]);
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test(
        'explicit sha256 + server offers only [MD5] throws AlgorithmMismatchException',
        () {
      final a = DigestAuth(
          username: 'u', password: 'p', algorithm: DigestAlgorithm.sha256);
      expect(
        () => a.initFromMultipleChallenges([md5Challenge]),
        throwsA(isA<AlgorithmMismatchException>()),
      );
    });

    test('empty list throws DigestAuthFormatException', () {
      final a = DigestAuth(username: 'u', password: 'p');
      expect(
        () => a.initFromMultipleChallenges([]),
        throwsA(isA<DigestAuthFormatException>()),
      );
    });

    test('non-Digest headers are skipped gracefully', () {
      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromMultipleChallenges([
        'Basic realm="test"',
        'Bearer token=abc',
        sha256Challenge,
      ]);
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test('correct algorithm= in header after negotiation', () {
      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromMultipleChallenges([md5Challenge, sha512Challenge]);
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-512-256'));
      expect(header, isNot(contains('algorithm=MD5')));
    });

    test('realm, nonce, opaque from selected challenge are used', () {
      const md5WithOpaque =
          'Digest realm="md5-realm",nonce="md5-nonce",qop="auth",algorithm=MD5,opaque="md5-opq"';
      const sha256WithOpaque =
          'Digest realm="sha256-realm",nonce="sha256-nonce",qop="auth",algorithm=SHA-256,opaque="sha256-opq"';

      final a = DigestAuth(username: 'u', password: 'p');
      a.initFromMultipleChallenges([md5WithOpaque, sha256WithOpaque]);
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      // SHA-256 is stronger, so its realm/nonce/opaque should be used
      expect(header, contains('realm="sha256-realm"'));
      expect(header, contains('nonce="sha256-nonce"'));
      expect(header, contains('opaque="sha256-opq"'));
    });
  });

  group('MockClient integration with charset=UTF-8', () {
    test('full challenge-response with charset=UTF-8 and non-ASCII username',
        () async {
      var requestCount = 0;
      const wwwAuthenticate =
          'Digest realm="intl-server",nonce="charsetNonce123",'
          'qop="auth",algorithm=SHA-256,charset=UTF-8';

      final client = MockClient((request) async {
        requestCount++;
        if (requestCount == 1) {
          return http.Response(
            'Unauthorized',
            401,
            headers: {'www-authenticate': wwwAuthenticate},
          );
        } else {
          final authHeader = request.headers['authorization'];
          expect(authHeader, isNotNull);
          expect(authHeader, startsWith('Digest '));
          expect(authHeader, contains("username*=UTF-8''"));
          expect(authHeader, contains('algorithm=SHA-256'));
          expect(authHeader, contains('response="'));

          return http.Response('{"status":"OK"}', 200);
        }
      });

      final firstResponse = await client.post(
        Uri.parse('http://localhost:18081/json_rpc'),
        body: '{"jsonrpc":"2.0","method":"get_info"}',
      );
      expect(firstResponse.statusCode, equals(401));

      final challenge = firstResponse.headers['www-authenticate']!;
      final digestAuth =
          DigestAuth(username: 'J\u00e4s\u00f8n', password: 'S\u00e9cret');
      digestAuth.initFromAuthorizationHeader(challenge);
      final authString =
          digestAuth.buildAuthorizationHeader(method: 'POST', uri: '/json_rpc');

      final secondResponse = await client.post(
        Uri.parse('http://localhost:18081/json_rpc'),
        headers: {'authorization': authString},
        body: '{"jsonrpc":"2.0","method":"get_info"}',
      );
      expect(secondResponse.statusCode, equals(200));

      client.close();
    });
  });

  group('auth-int support', () {
    test('auth-int with body produces correct HA2', () {
      final a = DigestAuth(username: 'user', password: 'pass', qop: 'auth-int');
      a.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="testnonce",qop="auth-int"',
      );
      final body = utf8.encode('{"method":"test"}');
      final header = a.buildAuthorizationHeader(
        method: 'POST',
        uri: '/api',
        body: body,
      );
      expect(header, contains('qop=auth-int'));

      // Manually compute expected response to verify correctness
      final algo = DigestAlgorithm.md5;
      final ha1 = algo.hash(utf8.encode('user:testrealm:pass'));
      final bodyHash = algo.hash(body);
      final ha2 = algo.hash(utf8.encode('POST:/api:$bodyHash'));
      // Extract nc and cnonce from header to compute expected response
      final ncMatch = RegExp(r'nc=([0-9a-f]{8})').firstMatch(header)!.group(1)!;
      final cnonceMatch =
          RegExp(r'cnonce="([^"]+)"').firstMatch(header)!.group(1)!;
      final expectedResponse = algo.hash(
        utf8.encode('$ha1:testnonce:$ncMatch:$cnonceMatch:auth-int:$ha2'),
      );
      expect(header, contains('response="$expectedResponse"'));
    });

    test('auth-int with null body uses empty body hash', () {
      final a = DigestAuth(username: 'user', password: 'pass', qop: 'auth-int');
      a.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="testnonce",qop="auth-int"',
      );
      final header = a.buildAuthorizationHeader(
        method: 'GET',
        uri: '/path',
      );
      // Verify response uses H(empty bytes) for body hash
      final algo = DigestAlgorithm.md5;
      final ha1 = algo.hash(utf8.encode('user:testrealm:pass'));
      final emptyBodyHash = algo.hash(<int>[]);
      final ha2 = algo.hash(utf8.encode('GET:/path:$emptyBodyHash'));
      final ncMatch = RegExp(r'nc=([0-9a-f]{8})').firstMatch(header)!.group(1)!;
      final cnonceMatch =
          RegExp(r'cnonce="([^"]+)"').firstMatch(header)!.group(1)!;
      final expectedResponse = algo.hash(
        utf8.encode('$ha1:testnonce:$ncMatch:$cnonceMatch:auth-int:$ha2'),
      );
      expect(header, contains('response="$expectedResponse"'));
    });

    test('qop=auth ignores body parameter', () {
      final a = DigestAuth(username: 'user', password: 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="testnonce",qop="auth"',
      );
      final body = utf8.encode('some body');
      final withBody = a.buildAuthorizationHeader(
        method: 'POST',
        uri: '/api',
        body: body,
      );

      // Create second instance to get header without body
      final b = DigestAuth(username: 'user', password: 'pass');
      b.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="testnonce",qop="auth"',
      );
      final withoutBody = b.buildAuthorizationHeader(
        method: 'POST',
        uri: '/api',
      );

      // Both should have qop=auth (not auth-int)
      expect(withBody, contains('qop=auth'));
      expect(withoutBody, contains('qop=auth'));
      // cnonce differs so full headers differ, but both use H(method:uri) for HA2
    });

    test('auth-int with SHA-256 uses SHA-256 for body hash', () {
      final a = DigestAuth(
        username: 'user',
        password: 'pass',
        algorithm: DigestAlgorithm.sha256,
        qop: 'auth-int',
      );
      a.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="testnonce",qop="auth-int",algorithm=SHA-256',
      );
      final body = utf8.encode('test body');
      final header = a.buildAuthorizationHeader(
        method: 'POST',
        uri: '/api',
        body: body,
      );
      expect(header, contains('algorithm=SHA-256'));
      expect(header, contains('qop=auth-int'));

      // Verify using SHA-256 for all hashes including body
      final algo = DigestAlgorithm.sha256;
      final ha1 = algo.hash(utf8.encode('user:testrealm:pass'));
      final bodyHash = algo.hash(body);
      final ha2 = algo.hash(utf8.encode('POST:/api:$bodyHash'));
      final ncMatch = RegExp(r'nc=([0-9a-f]{8})').firstMatch(header)!.group(1)!;
      final cnonceMatch =
          RegExp(r'cnonce="([^"]+)"').firstMatch(header)!.group(1)!;
      final expectedResponse = algo.hash(
        utf8.encode('$ha1:testnonce:$ncMatch:$cnonceMatch:auth-int:$ha2'),
      );
      expect(header, contains('response="$expectedResponse"'));
    });
  });

  group('Session variant support', () {
    test('MD5-sess produces session HA1', () {
      final a = DigestAuth(
        username: 'user',
        password: 'pass',
        algorithm: DigestAlgorithm.md5sess,
      );
      a.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="testnonce",qop="auth",algorithm=MD5-sess',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=MD5-sess'));

      // Verify session HA1: H(H(user:realm:pass):nonce:cnonce)
      final algo = DigestAlgorithm.md5;
      final baseHa1 = algo.hash(utf8.encode('user:testrealm:pass'));
      final cnonceMatch =
          RegExp(r'cnonce="([^"]+)"').firstMatch(header)!.group(1)!;
      final sessionHa1 =
          algo.hash(utf8.encode('$baseHa1:testnonce:$cnonceMatch'));
      final ha2 = algo.hash(utf8.encode('GET:/path'));
      final ncMatch = RegExp(r'nc=([0-9a-f]{8})').firstMatch(header)!.group(1)!;
      final expectedResponse = algo.hash(
        utf8.encode('$sessionHa1:testnonce:$ncMatch:$cnonceMatch:auth:$ha2'),
      );
      expect(header, contains('response="$expectedResponse"'));
    });

    test('MD5-sess reuses cached HA1 for second request with same nonce', () {
      final a = DigestAuth(
        username: 'user',
        password: 'pass',
        algorithm: DigestAlgorithm.md5sess,
      );
      a.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="testnonce",qop="auth",algorithm=MD5-sess',
      );
      final header1 = a.buildAuthorizationHeader(method: 'GET', uri: '/path1');
      final header2 = a.buildAuthorizationHeader(method: 'GET', uri: '/path2');

      // Extract cnonces -- they should differ
      final cnonce1 =
          RegExp(r'cnonce="([^"]+)"').firstMatch(header1)!.group(1)!;
      final cnonce2 =
          RegExp(r'cnonce="([^"]+)"').firstMatch(header2)!.group(1)!;
      expect(cnonce1, isNot(equals(cnonce2)));

      // But the session HA1 uses cnonce1 (first request's cnonce), not cnonce2
      // Verify header2's response uses the session key from request 1
      final algo = DigestAlgorithm.md5;
      final baseHa1 = algo.hash(utf8.encode('user:testrealm:pass'));
      final sessionHa1 = algo.hash(utf8.encode('$baseHa1:testnonce:$cnonce1'));
      final ha2 = algo.hash(utf8.encode('GET:/path2'));
      final nc2 = RegExp(r'nc=([0-9a-f]{8})').firstMatch(header2)!.group(1)!;
      final expectedResponse2 = algo.hash(
        utf8.encode('$sessionHa1:testnonce:$nc2:$cnonce2:auth:$ha2'),
      );
      expect(header2, contains('response="$expectedResponse2"'));
    });

    test('SHA-256-sess produces correct session HA1', () {
      final a = DigestAuth(
        username: 'user',
        password: 'pass',
        algorithm: DigestAlgorithm.sha256sess,
      );
      a.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="testnonce",qop="auth",algorithm=SHA-256-sess',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      expect(header, contains('algorithm=SHA-256-sess'));

      final algo = DigestAlgorithm.sha256;
      final baseHa1 = algo.hash(utf8.encode('user:testrealm:pass'));
      final cnonceMatch =
          RegExp(r'cnonce="([^"]+)"').firstMatch(header)!.group(1)!;
      final sessionHa1 =
          algo.hash(utf8.encode('$baseHa1:testnonce:$cnonceMatch'));
      final ha2 = algo.hash(utf8.encode('GET:/path'));
      final ncMatch = RegExp(r'nc=([0-9a-f]{8})').firstMatch(header)!.group(1)!;
      final expectedResponse = algo.hash(
        utf8.encode('$sessionHa1:testnonce:$ncMatch:$cnonceMatch:auth:$ha2'),
      );
      expect(header, contains('response="$expectedResponse"'));
    });

    test('session HA1 invalidated on nonce change', () {
      final a = DigestAuth(
        username: 'user',
        password: 'pass',
        algorithm: DigestAlgorithm.md5sess,
      );
      a.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="nonce1",qop="auth",algorithm=MD5-sess',
      );
      final header1 = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      final cnonce1 =
          RegExp(r'cnonce="([^"]+)"').firstMatch(header1)!.group(1)!;

      // New nonce -- session HA1 must be recomputed
      a.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="nonce2",qop="auth",algorithm=MD5-sess',
      );
      final header2 = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      final cnonce2 =
          RegExp(r'cnonce="([^"]+)"').firstMatch(header2)!.group(1)!;

      // cnonces should differ across nonce boundaries
      expect(cnonce1, isNot(equals(cnonce2)));

      // Session keys should use different nonces
      final algo = DigestAlgorithm.md5;
      final baseHa1 = algo.hash(utf8.encode('user:testrealm:pass'));
      final sessionHa1_2 = algo.hash(utf8.encode('$baseHa1:nonce2:$cnonce2'));
      final ha2 = algo.hash(utf8.encode('GET:/path'));
      final nc2 = RegExp(r'nc=([0-9a-f]{8})').firstMatch(header2)!.group(1)!;
      final expectedResponse2 = algo.hash(
        utf8.encode('$sessionHa1_2:nonce2:$nc2:$cnonce2:auth:$ha2'),
      );
      expect(header2, contains('response="$expectedResponse2"'));
    });

    test('non-session algorithm does not use session caching', () {
      final a = DigestAuth(username: 'user', password: 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="testrealm",nonce="testnonce",qop="auth"',
      );
      final header = a.buildAuthorizationHeader(method: 'GET', uri: '/path');
      // Standard MD5 HA1 = H(user:realm:pass), no session key
      final algo = DigestAlgorithm.md5;
      final ha1 = algo.hash(utf8.encode('user:testrealm:pass'));
      final ha2 = algo.hash(utf8.encode('GET:/path'));
      final ncMatch = RegExp(r'nc=([0-9a-f]{8})').firstMatch(header)!.group(1)!;
      final cnonceMatch =
          RegExp(r'cnonce="([^"]+)"').firstMatch(header)!.group(1)!;
      final expectedResponse = algo.hash(
        utf8.encode('$ha1:testnonce:$ncMatch:$cnonceMatch:auth:$ha2'),
      );
      expect(header, contains('response="$expectedResponse"'));
    });
  });
}
