import 'dart:convert';
import 'dart:math' as math;

import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';

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
  int _nonceCount = 0;

  DigestAuth(this.username, this.password);

  /// Initialize Digest parameters from the `WWW-Authenticate` header.
  void initFromAuthorizationHeader(String authInfo) {
    final Map<String, String>? values = _splitAuthenticateHeader(authInfo);
    if (values != null) {
      realm = values['realm'];
      // Check if the nonce has changed.
      if (nonce != values['nonce']) {
        nonce = values['nonce'];
        _nonceCount = 0; // Reset nonce count when nonce changes.
      }
    }
  }

  /// Generate the Digest Authorization header.
  String getAuthString(String method, String uri) {
    this.uri = uri;
    _nonceCount++;
    String cnonce = _computeCnonce();
    String nc = _formatNonceCount(_nonceCount);

    String ha1 = md5Hash("$username:$realm:$password");
    String ha2 = md5Hash("$method:$uri");
    String response = md5Hash("$ha1:$nonce:$nc:$cnonce:$qop:$ha2");

    return 'Digest username="$username", realm="$realm", nonce="$nonce", uri="$uri", qop=$qop, nc=$nc, cnonce="$cnonce", response="$response"';
  }

  /// Helper to parse the `WWW-Authenticate` header.
  Map<String, String>? _splitAuthenticateHeader(String? header) {
    if (header == null || !header.startsWith('Digest ')) {
      return null;
    }
    String token = header.substring(7); // Remove 'Digest '.
    final Map<String, String> result = {};

    final components = token.split(',').map((token) => token.trim());
    for (final component in components) {
      final kv = component.split('=');
      final key = kv[0];
      final value = kv.sublist(1).join('=').replaceAll('"', '');
      result[key] = value;
    }
    return result;
  }

  /// Helper to compute a random cnonce.
  String _computeCnonce() {
    final math.Random rnd = math.Random();
    final List<int> values = List<int>.generate(16, (i) => rnd.nextInt(256));
    return hex.encode(values);
  }

  /// Helper to format the nonce count.
  String _formatNonceCount(int count) =>
      count.toRadixString(16).padLeft(8, '0');

  /// Compute the MD5 hash of a string.
  String md5Hash(String input) {
    return md5.convert(utf8.encode(input)).toString();
  }
}
