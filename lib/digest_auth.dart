/// HTTP Digest Authentication (RFC 7616).
library;

export 'src/algorithm.dart';
export 'src/errors.dart';

import 'dart:convert';
import 'dart:math' as math;

import 'package:convert/convert.dart';
import 'package:unorm_dart/unorm_dart.dart' as unorm;

import 'src/algorithm.dart';
import 'src/errors.dart';

/// HTTP Digest authentication.
///
/// Adapted from https://github.com/dart-lang/http/issues/605#issue-963962341.
///
/// Created because http_auth was not working for Monero daemon RPC responses.
class DigestAuth {
  final String _username;
  final String _password;
  String? _realm;
  String? _nonce;
  String? _uri;
  final String _qop;
  String? _opaque;
  final DigestAlgorithm? _userAlgorithm;
  DigestAlgorithm _activeAlgorithm;
  bool _charsetUtf8 = false;
  int _nonceCount = 0;
  String? _sessionHa1;
  String? _sessionHa1Nonce;

  String get username => _username;
  String get password => _password;
  String? get realm => _realm;
  String? get nonce => _nonce;
  String? get uri => _uri;
  String? get opaque => _opaque;
  String get qop => _qop;

  /// Explicit [algorithm] is validated against the server challenge.
  /// Omit to auto-negotiate (defaults to MD5 per RFC 2617).
  DigestAuth({
    required String username,
    required String password,
    DigestAlgorithm? algorithm,
    String qop = 'auth',
  })  : _username = username,
        _password = password,
        _userAlgorithm = algorithm,
        _activeAlgorithm = algorithm ?? DigestAlgorithm.md5,
        _qop = qop;

  /// Parse a `WWW-Authenticate` header and update internal state.
  ///
  /// Throws [DigestAuthFormatException] on malformed input.
  /// Throws [StaleNonceException] if stale=true (nonce already updated).
  void initFromAuthorizationHeader(String? authInfo) {
    if (authInfo == null || authInfo.isEmpty) {
      throw DigestAuthFormatException('Authorization header is null or empty');
    }

    final Map<String, String> values = _parseAuthenticateHeader(authInfo);

    _realm = values['realm'];
    _opaque = values['opaque'];

    // Algorithm negotiation.
    final serverAlgorithm = values['algorithm'];
    if (serverAlgorithm != null) {
      final offered = DigestAlgorithm.fromHeaderValue(serverAlgorithm);
      if (_userAlgorithm != null) {
        if (offered == null || offered != _userAlgorithm) {
          throw AlgorithmMismatchException(
            'Server offers algorithm=$serverAlgorithm but caller requires ${_userAlgorithm.headerValue}',
          );
        }
      } else if (offered != null) {
        _activeAlgorithm = offered;
      }
    }

    // charset=UTF-8 (RFC 7616 S4).
    final charset = values['charset'];
    _charsetUtf8 = charset != null && charset.toUpperCase() == 'UTF-8';

    if (_nonce != values['nonce']) {
      _nonce = values['nonce'];
      _nonceCount = 0;
      _sessionHa1 = null;
      _sessionHa1Nonce = null;
    }

    // Stale check must come after nonce update.
    final stale = values['stale'];
    if (stale != null && stale.toLowerCase() == 'true') {
      throw StaleNonceException(
        'Server indicated nonce is stale. Nonce has been updated -- retry with buildAuthorizationHeader().',
      );
    }
  }

  /// Select the strongest algorithm from multiple WWW-Authenticate challenges.
  ///
  /// Honors explicit [algorithm] if set; otherwise picks strongest per
  /// RFC 7616 S3.4.
  void initFromMultipleChallenges(List<String> challenges) {
    if (challenges.isEmpty) {
      throw DigestAuthFormatException(
        'No WWW-Authenticate challenges provided',
      );
    }

    final parsed = <DigestAlgorithm, String>{};
    for (final challenge in challenges) {
      if (!challenge.startsWith('Digest ')) continue;
      final params = _parseAuthenticateHeader(challenge);
      final algoStr = params['algorithm'];
      final algo = algoStr != null
          ? DigestAlgorithm.fromHeaderValue(algoStr)
          : DigestAlgorithm.md5;
      if (algo != null) {
        parsed[algo] = challenge;
      }
    }

    if (parsed.isEmpty) {
      throw DigestAuthFormatException(
        'No valid Digest challenges found in provided headers',
      );
    }

    if (_userAlgorithm != null) {
      final match = parsed[_userAlgorithm];
      if (match == null) {
        final offered = parsed.keys.map((a) => a.headerValue).join(', ');
        throw AlgorithmMismatchException(
          'Server offers [$offered] but caller requires ${_userAlgorithm.headerValue}',
        );
      }
      initFromAuthorizationHeader(match);
    } else {
      final algorithms = parsed.keys.map((a) => a.headerValue).toList();
      final strongest = DigestAlgorithm.selectStrongest(algorithms);
      initFromAuthorizationHeader(parsed[strongest]!);
    }
  }

  /// Build the Digest Authorization header value.
  ///
  /// For qop=auth-int, [body] bytes are hashed into HA2. Ignored for qop=auth.
  String buildAuthorizationHeader({
    required String method,
    required String uri,
    List<int>? body,
  }) {
    _uri = uri;
    _nonceCount++;
    String cnonce = _computeCnonce();
    String nc = _formatNonceCount(_nonceCount);

    // NFC-normalize credentials when charset=UTF-8.
    final effectiveUsername = _charsetUtf8 ? unorm.nfc(_username) : _username;
    final effectivePassword = _charsetUtf8 ? unorm.nfc(_password) : _password;

    String ha1 = _computeHa1(cnonce, effectiveUsername, effectivePassword);

    String ha2;
    if (_qop == 'auth-int') {
      final bodyBytes = body ?? <int>[];
      final bodyHash = _activeAlgorithm.hash(bodyBytes);
      ha2 = _activeAlgorithm.hash(utf8.encode('$method:$uri:$bodyHash'));
    } else {
      ha2 = _activeAlgorithm.hash(utf8.encode('$method:$uri'));
    }

    String response = _activeAlgorithm
        .hash(utf8.encode('$ha1:$_nonce:$nc:$cnonce:$_qop:$ha2'));

    // Non-ASCII username → RFC 5987 username* encoding.
    final bool hasNonAscii = _username.codeUnits.any((c) => c > 127);
    final String usernameParam;
    if (_charsetUtf8 && hasNonAscii) {
      usernameParam = 'username*=${_encodeExtValue(effectiveUsername)}';
    } else {
      usernameParam = 'username="$effectiveUsername"';
    }

    var header = 'Digest $usernameParam, realm="$_realm", nonce="$_nonce", '
        'uri="$uri", algorithm=${_activeAlgorithm.headerValue}, '
        'qop=$_qop, nc=$nc, cnonce="$cnonce", response="$response"';

    if (_charsetUtf8) {
      header += ', userhash=false';
    }

    if (_opaque != null) {
      header += ', opaque="$_opaque"';
    }

    return header;
  }

  @Deprecated('Use buildAuthorizationHeader() instead')
  String getAuthString(String method, String uri) =>
      buildAuthorizationHeader(method: method, uri: uri);

  /// Quoted-string-aware WWW-Authenticate header parser.
  Map<String, String> _parseAuthenticateHeader(String header) {
    if (!header.startsWith('Digest ')) {
      throw DigestAuthFormatException(
        'Expected Digest challenge, got: ${header.length > 20 ? '${header.substring(0, 20)}...' : header}',
      );
    }

    final params = <String, String>{};
    final token = header.substring(7);

    var key = StringBuffer();
    var value = StringBuffer();
    var inQuotes = false;
    var parsingValue = false;

    for (var i = 0; i < token.length; i++) {
      final c = token[i];

      if (c == '"' && parsingValue) {
        inQuotes = !inQuotes;
        continue;
      }

      if (c == '=' && !parsingValue && !inQuotes) {
        parsingValue = true;
        continue;
      }

      if (c == ',' && !inQuotes) {
        final k = key.toString().trim();
        if (k.isNotEmpty) {
          params[k] = value.toString().trim();
        }
        key = StringBuffer();
        value = StringBuffer();
        parsingValue = false;
        continue;
      }

      if (parsingValue) {
        value.write(c);
      } else {
        key.write(c);
      }
    }

    final k = key.toString().trim();
    if (k.isNotEmpty) {
      params[k] = value.toString().trim();
    }

    return params;
  }

  String _computeCnonce() {
    final math.Random rnd = math.Random.secure();
    final List<int> values = List<int>.generate(16, (i) => rnd.nextInt(256));
    return hex.encode(values);
  }

  String _formatNonceCount(int count) =>
      count.toRadixString(16).padLeft(8, '0');

  /// Compute HA1 with session variant caching for -sess algorithms.
  ///
  /// For -sess variants, caches H(H(user:realm:pass):nonce:cnonce)
  /// per nonce so subsequent requests reuse the same session key.
  String _computeHa1(
    String cnonce,
    String effectiveUsername,
    String effectivePassword,
  ) {
    final baseHa1 = _activeAlgorithm.hash(
      utf8.encode('$effectiveUsername:$_realm:$effectivePassword'),
    );

    if (!_activeAlgorithm.isSession) return baseHa1;

    // Reuse cached session key if nonce hasn't changed.
    if (_sessionHa1 != null && _sessionHa1Nonce == _nonce) {
      return _sessionHa1!;
    }

    _sessionHa1 = _activeAlgorithm.hash(
      utf8.encode('$baseHa1:$_nonce:$cnonce'),
    );
    _sessionHa1Nonce = _nonce;
    return _sessionHa1!;
  }

  /// RFC 5987 ext-value encoding: UTF-8''percent-encoded.
  String _encodeExtValue(String value) {
    final bytes = utf8.encode(value);
    final buffer = StringBuffer("UTF-8''");
    for (final byte in bytes) {
      if (_isAttrChar(byte)) {
        buffer.writeCharCode(byte);
      } else {
        buffer
            .write('%${byte.toRadixString(16).padLeft(2, '0').toUpperCase()}');
      }
    }
    return buffer.toString();
  }

  /// RFC 5987 attr-char check.
  bool _isAttrChar(int byte) {
    return (byte >= 0x41 && byte <= 0x5A) || // A-Z
        (byte >= 0x61 && byte <= 0x7A) || // a-z
        (byte >= 0x30 && byte <= 0x39) || // 0-9
        byte == 0x21 || // !
        byte == 0x23 || // #
        byte == 0x24 || // $
        byte == 0x26 || // &
        byte == 0x2B || // +
        byte == 0x2D || // -
        byte == 0x2E || // .
        byte == 0x5E || // ^
        byte == 0x5F || // _
        byte == 0x60 || // `
        byte == 0x7C || // |
        byte == 0x7E; // ~
  }
}
