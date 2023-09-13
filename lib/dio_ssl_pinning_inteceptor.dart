import 'dart:io';

import 'package:dio_ssl_pinning/dio_ssl_pinning.dart';

class DioSslPinningInteceptor extends Interceptor {
  final List<String> certificate;

  DioSslPinningInteceptor({required this.certificate});

  @override
  Future<void> onRequest(
      RequestOptions options, RequestInterceptorHandler handler) async {
    try {
      final uri = options.uri;
      final host = uri.host;
      final port = uri.port;

      // Open a socket connection to retrieve the server's certificate
      final socket = await SecureSocket.connect(host, port);
      final receivedCertificate = socket.peerCertificate?.pem;
      socket.close();

      // Check if the received match the trusted certificates
      final matchingCertificates = certificate.contains(receivedCertificate);

      if (!matchingCertificates) {
        throw DioException(
          error: const TlsException('No matching certificates found'),
          requestOptions: options,
        );
      }

      handler.next(options);
    } catch (e) {
      if (e is DioException) {
        handler.reject(e);
      } else {
        handler.reject(DioException(requestOptions: options, error: e));
      }
    }
  }
}
