export 'src/algorithm.dart';
export 'src/errors.dart';

import 'dart:convert';
import 'dart:math' as math;

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';

import 'src/algorithm.dart';
import 'src/errors.dart';

/// HTTP Digest authentication.
///
/// Adapted from https://github.com/dart-lang/http/issues/605#issue-963962341.
///
/// Created because http_auth was not working for Monero daemon RPC responses.
class DigestAuth {
  final String username;
  final String password;
  String? realm;
  String? nonce;
  String? uri;
  String? qop = "auth";
  String? opaque;
  final DigestAlgorithm _algorithm;
  int _nonceCount = 0;

  DigestAuth(this.username, this.password,
      {DigestAlgorithm algorithm = DigestAlgorithm.md5})
      : _algorithm = algorithm;

  /// Parse a `WWW-Authenticate` header and update internal state.
  ///
  /// Throws [DigestAuthFormatException] on malformed input.
  /// Throws [StaleNonceException] if stale=true (nonce already updated).
  void initFromAuthorizationHeader(String? authInfo) {
    if (authInfo == null || authInfo.isEmpty) {
      throw DigestAuthFormatException('Authorization header is null or empty');
    }

    final Map<String, String> values = _parseAuthenticateHeader(authInfo);

    realm = values['realm'];
    opaque = values['opaque'];

    // Check if the nonce has changed.
    if (nonce != values['nonce']) {
      nonce = values['nonce'];
      _nonceCount = 0; // Reset nonce count when nonce changes.
    }

    // Stale check must come after nonce update.
    final stale = values['stale'];
    if (stale != null && stale.toLowerCase() == 'true') {
      throw StaleNonceException(
        'Server indicated nonce is stale. Nonce has been updated -- retry with getAuthString().',
      );
    }
  }

  /// Generate the Digest Authorization header.
  String getAuthString(String method, String uri) {
    this.uri = uri;
    _nonceCount++;
    String cnonce = _computeCnonce();
    String nc = _formatNonceCount(_nonceCount);

    String ha1 = _algorithm.hash(utf8.encode("$username:$realm:$password"));
    String ha2 = _algorithm.hash(utf8.encode("$method:$uri"));
    String response =
        _algorithm.hash(utf8.encode("$ha1:$nonce:$nc:$cnonce:$qop:$ha2"));

    var header = 'Digest username="$username", realm="$realm", nonce="$nonce", '
        'uri="$uri", qop=$qop, nc=$nc, cnonce="$cnonce", '
        'response="$response", algorithm=${_algorithm.headerValue}';

    if (opaque != null) {
      header += ', opaque="$opaque"';
    }

    return header;
  }

  /// Parse WWW-Authenticate header with quoted-string awareness.
  Map<String, String> _parseAuthenticateHeader(String header) {
    if (!header.startsWith('Digest ')) {
      throw DigestAuthFormatException(
        'Expected Digest challenge, got: ${header.length > 20 ? '${header.substring(0, 20)}...' : header}',
      );
    }

    final params = <String, String>{};
    final token = header.substring(7); // Remove 'Digest '

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

    // Last param (no trailing comma).
    final k = key.toString().trim();
    if (k.isNotEmpty) {
      params[k] = value.toString().trim();
    }

    return params;
  }

  /// Helper to compute a random cnonce.
  String _computeCnonce() {
    final math.Random rnd = math.Random.secure();
    final List<int> values = List<int>.generate(16, (i) => rnd.nextInt(256));
    return hex.encode(values);
  }

  /// Helper to format the nonce count.
  String _formatNonceCount(int count) =>
      count.toRadixString(16).padLeft(8, '0');

  @Deprecated('Use DigestAlgorithm.md5.hash() instead.')
  String md5Hash(String input) {
    return md5.convert(utf8.encode(input)).toString();
  }
}
