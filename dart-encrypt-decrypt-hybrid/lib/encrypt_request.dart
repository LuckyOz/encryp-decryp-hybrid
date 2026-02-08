class EncryptRequest {
  final String data;
  final String? aes;
  final String iv;

  EncryptRequest({
    required this.data,
    this.aes,
    required this.iv,
  });

  factory EncryptRequest.fromJson(Map<String, dynamic> json) {
    return EncryptRequest(
      data: json['data'] ?? '',
      aes: json['aes'],
      iv: json['iv'] ?? '',
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'data': data,
      'aes': aes,
      'iv': iv,
    };
  }
}
