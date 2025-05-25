import 'dart:convert';

import 'package:crypto/crypto.dart' as crypto;
import 'package:digest_auth/digest_auth.dart';
import 'package:http/http.dart' as http;
import 'package:http/testing.dart';
import 'package:test/test.dart';

void main() {
  late DigestAuth auth;

  setUp(() {
    auth = DigestAuth('testuser', 'testpass');
  });

  group('DigestAuth constructor', () {
    test('creates instance with username and password accessible', () {
      expect(auth.username, equals('testuser'));
      expect(auth.password, equals('testpass'));
    });

    test('initial state has null realm, null nonce, null opaque, qop defaults to "auth"', () {
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
      auth.getAuthString('GET', '/path');
      final second = auth.getAuthString('GET', '/path');
      expect(second, contains('nc=00000002'));

      // Change nonce -- nc should reset
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="nonce2",qop="auth"',
      );
      final afterReset = auth.getAuthString('GET', '/path');
      expect(afterReset, contains('nc=00000001'));
    });
  });

  group('getAuthString', () {
    test('generates valid Digest header', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="monero-rpc",nonce="testnonce",qop="auth"',
      );
      final header = auth.getAuthString('POST', '/json_rpc');

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
      final header = auth.getAuthString('GET', '/path');
      expect(header, contains('opaque="opq123"'));
    });

    test('opaque NOT in output when absent', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = auth.getAuthString('GET', '/path');
      expect(header, isNot(contains('opaque')));
    });
  });

  group('cnonce security', () {
    test('two consecutive calls produce different cnonce values', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header1 = auth.getAuthString('GET', '/path');
      final header2 = auth.getAuthString('GET', '/path');

      final cnonceRegex = RegExp(r'cnonce="([^"]+)"');
      final cnonce1 = cnonceRegex.firstMatch(header1)!.group(1)!;
      final cnonce2 = cnonceRegex.firstMatch(header2)!.group(1)!;

      expect(cnonce1, isNot(equals(cnonce2)));
    });

    test('cnonce is 32 hex characters', () {
      auth.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = auth.getAuthString('GET', '/path');

      final cnonceRegex = RegExp(r'cnonce="([^"]+)"');
      final cnonce = cnonceRegex.firstMatch(header)!.group(1)!;

      expect(RegExp(r'^[0-9a-f]{32}$').hasMatch(cnonce), isTrue);
    });
  });

  group('md5Hash', () {
    test('known MD5 vector', () {
      // ignore: deprecated_member_use_from_same_package
      expect(auth.md5Hash('test'), equals('098f6bcd4621d373cade4e832627b4f6'));
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
      final digestAuth = DigestAuth('testuser', 'testpass');
      digestAuth.initFromAuthorizationHeader(challenge);
      final authString = digestAuth.getAuthString('POST', '/json_rpc');

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
      expect(DigestAlgorithm.fromHeaderValue('SHA-256'), equals(DigestAlgorithm.sha256));
      expect(DigestAlgorithm.fromHeaderValue('sha-256'), equals(DigestAlgorithm.sha256));
      expect(DigestAlgorithm.fromHeaderValue('Sha-256'), equals(DigestAlgorithm.sha256));
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
      expect(DigestAlgorithm.sha512_256.strength, greaterThan(DigestAlgorithm.sha256.strength));
      expect(DigestAlgorithm.sha256.strength, greaterThan(DigestAlgorithm.md5.strength));
    });
  });

  group('RFC 7616 S3.9.1 test vectors', () {
    String computeResponse(DigestAlgorithm algo, String username,
        String password, String realm, String nonce, String nc, String cnonce,
        String qop, String method, String uri) {
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
      expect(response, equals('753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1'));
    });

    test('SHA-512/256 primitive: NIST FIPS 180-4 vector', () {
      expect(
        DigestAlgorithm.sha512_256.hash(utf8.encode('abc')),
        equals('53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23'),
      );
    });

    test('SHA-512/256 digest auth vector (independently computed)', () {
      final response = computeResponse(DigestAlgorithm.sha512_256, username,
          password, realm, nonce, nc, cnonce, qop, method, uri);
      final ha1 = DigestAlgorithm.sha512_256.hash(
          utf8.encode('$username:$realm:$password'));
      final ha2 = DigestAlgorithm.sha512_256.hash(
          utf8.encode('$method:$uri'));
      final expected = DigestAlgorithm.sha512_256.hash(
          utf8.encode('$ha1:$nonce:$nc:$cnonce:$qop:$ha2'));
      expect(response, equals(expected));
    });
  });

  group('DigestAuth with algorithms', () {
    test('default constructor produces header with algorithm=MD5', () {
      final a = DigestAuth('u', 'p');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('algorithm=MD5'));
    });

    test('sha256 constructor produces header with algorithm=SHA-256', () {
      final a = DigestAuth('u', 'p', algorithm: DigestAlgorithm.sha256);
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test('sha512_256 constructor produces header with algorithm=SHA-512-256', () {
      final a = DigestAuth('u', 'p', algorithm: DigestAlgorithm.sha512_256);
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="abc",qop="auth"',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('algorithm=SHA-512-256'));
    });

    test('default constructor backward compatible', () {
      final a = DigestAuth('testuser', 'testpass');
      a.initFromAuthorizationHeader(
        'Digest realm="monero-rpc",nonce="testnonce",qop="auth"',
      );
      final header = a.getAuthString('POST', '/json_rpc');
      expect(header, startsWith('Digest '));
      expect(header, contains('username="testuser"'));
      expect(header, contains('realm="monero-rpc"'));
      expect(header, contains('response="'));
    });
  });

  group('Algorithm negotiation', () {
    test('auto-selects algorithm from server challenge', () {
      final a = DigestAuth('u', 'p');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth",algorithm=SHA-256',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test('explicit algorithm matches server -- no error', () {
      final a = DigestAuth('u', 'p', algorithm: DigestAlgorithm.sha256);
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth",algorithm=SHA-256',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test('explicit algorithm mismatches server -- throws AlgorithmMismatchException', () {
      final a = DigestAuth('u', 'p', algorithm: DigestAlgorithm.sha256);
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
      final a = DigestAuth('u', 'p', algorithm: DigestAlgorithm.sha256);
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth"',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('algorithm=SHA-256'));
    });

    test('no algorithm from either side defaults to MD5', () {
      final a = DigestAuth('u', 'p');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth"',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('algorithm=MD5'));
    });

    test('case-insensitive algorithm matching from server', () {
      final a = DigestAuth('u', 'p');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth",algorithm=sha-256',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('algorithm=SHA-256'));
    });
  });

  group('QOP configuration', () {
    test('default qop is auth', () {
      final a = DigestAuth('u', 'p');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth"',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('qop=auth'));
    });

    test('custom qop via constructor', () {
      final a = DigestAuth('u', 'p', qop: 'auth-int');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n1",qop="auth-int"',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('qop=auth-int'));
    });

    test('qop getter returns configured value', () {
      final a = DigestAuth('u', 'p', qop: 'auth-int');
      expect(a.qop, equals('auth-int'));
    });
  });

  group('md5Hash deprecation', () {
    test('md5Hash still works correctly', () {
      // ignore: deprecated_member_use_from_same_package
      expect(auth.md5Hash('test'), equals('098f6bcd4621d373cade4e832627b4f6'));
    });
  });

  group('charset=UTF-8 handling', () {
    test('ASCII username with charset=UTF-8 uses regular username param', () {
      final a = DigestAuth('Mufasa', 'Circle of Life');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('username="Mufasa"'));
      expect(header, isNot(contains('username*')));
    });

    test('non-ASCII username with charset=UTF-8 uses username* param', () {
      final a = DigestAuth('J\u00e4s\u00f8n Doe', 'Secret');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains("username*=UTF-8''J%C3%A4s%C3%B8n%20Doe"));
      expect(header, isNot(contains('username="')));
    });

    test('no charset in challenge -- no username* regardless of content', () {
      final a = DigestAuth('J\u00e4s\u00f8n', 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth"',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('username="J\u00e4s\u00f8n"'));
      expect(header, isNot(contains('username*')));
    });

    test('NFC normalization -- decomposed and precomposed produce same hash', () {
      // decomposed a-umlaut: a + combining diaeresis
      final authNFD = DigestAuth('J\u0061\u0308n', 'pass');
      // precomposed a-umlaut
      final authNFC = DigestAuth('J\u00e4n', 'pass');

      const challenge =
          'Digest realm="test",nonce="fixedNonce",qop="auth",charset=UTF-8';
      authNFD.initFromAuthorizationHeader(challenge);
      authNFC.initFromAuthorizationHeader(challenge);

      final headerNFD = authNFD.getAuthString('GET', '/path');
      final headerNFC = authNFC.getAuthString('GET', '/path');

      // The cnonces differ so responses will differ. Instead, verify both
      // produce a username* with the same NFC-encoded value.
      final usernameStarRegex = RegExp(r"username\*=UTF-8''([^ ,]+)");
      final userNFD = usernameStarRegex.firstMatch(headerNFD)!.group(1)!;
      final userNFC = usernameStarRegex.firstMatch(headerNFC)!.group(1)!;
      expect(userNFD, equals(userNFC),
          reason: 'NFC normalization should produce identical username* values');

      // Also verify the encoded form is the precomposed a-umlaut
      expect(userNFD, equals('J%C3%A4n'));
    });

    test('charset=UTF-8 case-insensitive', () {
      final a = DigestAuth('J\u00e4n', 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=utf-8',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains("username*=UTF-8''"));
    });

    test('userhash=false included when charset=UTF-8 active', () {
      final a = DigestAuth('user', 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('userhash=false'));
    });

    test('userhash not included when charset not present', () {
      final a = DigestAuth('user', 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth"',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, isNot(contains('userhash')));
    });
  });

  group('RFC 5987 ext-value encoding', () {
    test('space encoded as %20', () {
      final a = DigestAuth('J\u00e4n Doe', 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('%20'));
      expect(header, isNot(contains('username*=UTF-8\'\'J%C3%A4n+Doe')));
    });

    test('special attr-chars not encoded', () {
      // Use a username with attr-chars that should NOT be percent-encoded
      // Plus a non-ASCII char to trigger username*
      final a = DigestAuth('u\u00e4!#\$&+-.^_`|~', 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.getAuthString('GET', '/path');
      // The attr-chars should appear literally (unencoded) in the username* value
      expect(header, contains('!#\$&+-.^_`|~'));
    });

    test('multi-byte UTF-8 correctly percent-encoded', () {
      // CJK character U+4E16 (world) is 3 bytes in UTF-8: E4 B8 96
      final a = DigestAuth('\u4e16', 'pass');
      a.initFromAuthorizationHeader(
        'Digest realm="test",nonce="n",qop="auth",charset=UTF-8',
      );
      final header = a.getAuthString('GET', '/path');
      expect(header, contains('%E4%B8%96'));
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
      final digestAuth = DigestAuth('J\u00e4s\u00f8n', 'S\u00e9cret');
      digestAuth.initFromAuthorizationHeader(challenge);
      final authString = digestAuth.getAuthString('POST', '/json_rpc');

      final secondResponse = await client.post(
        Uri.parse('http://localhost:18081/json_rpc'),
        headers: {'authorization': authString},
        body: '{"jsonrpc":"2.0","method":"get_info"}',
      );
      expect(secondResponse.statusCode, equals(200));

      client.close();
    });
  });
}
