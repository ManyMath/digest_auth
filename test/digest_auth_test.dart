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
}
