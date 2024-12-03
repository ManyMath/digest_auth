import 'dart:convert';

import 'package:digest_auth/digest_auth.dart';
import 'package:http/http.dart' as http;
import 'package:test/test.dart';

// Copied from the monero_rpc package in order to avoid recursive dependencies.
class DaemonRpc {
  final String rpcUrl;
  final String username;
  final String password;

  DaemonRpc(this.rpcUrl, {required this.username, required this.password});

  /// Perform a JSON-RPC call with Digest Authentication.
  Future<Map<String, dynamic>> call(
      String method, Map<String, dynamic> params) async {
    final http.Client client = http.Client();
    final DigestAuth digestAuth = DigestAuth(username, password);

    // Initial request to get the `WWW-Authenticate` header.
    final initialResponse = await client.post(
      Uri.parse(rpcUrl),
      headers: {
        'Content-Type': 'application/json',
      },
      body: jsonEncode({
        'jsonrpc': '2.0',
        'id': '0',
        'method': method,
        'params': params,
      }),
    );

    if (initialResponse.statusCode != 401 ||
        !initialResponse.headers.containsKey('www-authenticate')) {
      throw Exception('Unexpected response: ${initialResponse.body}');
    }

    // Extract Digest details from `WWW-Authenticate` header.
    final String authInfo = initialResponse.headers['www-authenticate']!;
    digestAuth.initFromAuthorizationHeader(authInfo);

    // Create Authorization header for the second request.
    String uri = Uri.parse(rpcUrl).path;
    int nonceCount = 1; // Start with 1 and increment for subsequent requests.
    String authHeader = digestAuth.getAuthString('POST', uri, nonceCount);

    // Make the authenticated request.
    final authenticatedResponse = await client.post(
      Uri.parse(rpcUrl),
      headers: {
        'Content-Type': 'application/json',
        'Authorization': authHeader,
      },
      body: jsonEncode({
        'jsonrpc': '2.0',
        'id': '0',
        'method': method,
        'params': params,
      }),
    );

    if (authenticatedResponse.statusCode != 200) {
      throw Exception('RPC call failed: ${authenticatedResponse.body}');
    }

    final Map<String, dynamic> result = jsonDecode(authenticatedResponse.body);
    if (result['error'] != null) {
      throw Exception('RPC Error: ${result['error']}');
    }

    return result['result'];
  }
}

void main() {
  test('WalletRpc call method', () async {
    final walletRpc = DaemonRpc(
      'http://localhost:18081/json_rpc',
      username: 'user',
      password: 'password',
    );

    final result = await walletRpc.call('get_info', {});
    expect(result, isA<Map<String, dynamic>>());
  });
}
