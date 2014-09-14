library jwt.jwa.test;


import 'package:unittest/unittest.dart';
import 'package:dart_jwt/src/jws.dart';
import 'package:dart_jwt/src/jwa.dart';
import 'package:googleapis_auth/src/crypto/rsa.dart';
import 'package:googleapis_auth/src/crypto/pem.dart';

void main()  {
  group('[HS256]', () {
    String sign(String signingInput, String sharedSecret) {
      final jwsSignature = new JwsSignature.create(signingInput, JsonWebAlgorithm.HS256, 
          new JwaSignatureContext(sharedSecret));
      return jwsSignature.encode();
    }
    
    // TODO: very adhoc - just two examples
    test('case 1', () {
      expect(sign('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                  'eyJpYXQiOjEzOTU3MjUxMzYsImV4cCI6MTM5NTcyNTMxNiwiaXNzIjoiZm9v'
                  'LWJhci1hZGRvbiIsInFzaCI6IjEzODU2Zjk3ZWU3ZTE2ZjE1YmFmY2QxYjZh'
                  'MzE3MDQ4NWE2Mjk2NGIzYWU5MTU0ZTMyZWUyNjdhNjA4OTM0M2MifQ',
                  '5b51a6d1-0628-4ade-b9d7-83290e7e433a'), 
                  equals('s4WJ6h4glblp-GiVVAOuGxQRQ0Sb3wpnRvKXbmZXgT8'));
    });
    test('case 2', () {
      expect(sign('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
                  'eyJpYXQiOjEzOTU3Mjg5MzcsImV4cCI6MTM5NTcyOTExNywiaXNzIjoiZm9v'
                  'LWJhci1hZGRvbiIsInFzaCI6IjEzODU2Zjk3ZWU3ZTE2ZjE1YmFmY2QxYjZh'
                  'MzE3MDQ4NWE2Mjk2NGIzYWU5MTU0ZTMyZWUyNjdhNjA4OTM0M2MifQ',
                  'bd630768-3f4c-49c7-a414-4f44b4ec021b'), 
                  equals('NDrBMAzry_r-VRFM2r0hVaKAQdFtlTht_Qs4Mn5l0MI'));
    });
  });

  // Generate pub/private RSA key:
  // openssl req -x509 -days 365 -newkey rsa:2048 -sha1 -nodes  \
  // -subj '/C=DK/L=Copenhagen/CN=www.example.com' \
  // -keyout testkey.pem -out testcert.pem
  group('[RS256]', () {
    var rsaPrivatePem = '''
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDN/NANYyAzimKV
TXZpttmnpJORcK1iQZOkHmyFO/bbM5tR4Z5b1Mu5kMJq+Nf0SmgRsrEGxF8uL3Sy
sZjbMa2DtS9lEdB8rSJvzjlI552CGpwmqtSNOe4e56vMHYB45OYH+EZEUb4oRyLq
+ZSUURL/du1HXVEzrx8dedCLsMtGKLiQcpolVRzydJJLJIIbg8fzin6X5KIgM06L
M3NpB3MaKFc1ouzgNWlJ3BbwLOBKIlyKhQPXpw5cUPcIJ+VGGA/JbcrCMFnAqVaR
IYwKbcFP983hsDLbQJKfZogsXhdi8W+7LnHtBD80kusZbgwC52mP1VQmoDT+zcWF
UAp9ZLCPAgMBAAECggEAAweo98lxe9CZSqDtEPkDkpe1I/qIUl2skklwRzVumCLW
Mgojji4/IOekNHaclpdRmJEMUZEp5UAFc2txWCgO6VUM8WulqW/Shdp+tTfS9Ur2
6QqyPbGQcxvtRv9YGG8lgxB/2BlrtqP1O4eYS+Y1ZVSWgOo6e4wj5QcZrjRXiRyh
c48XPRsA/RUfMgOmVYUsEFeBgvXLIT1PqSG2eqC40E8CDChwRdWNy5b5zgvHWN7r
+2O+iu7dumJkxiGXcSWOvdHlPqP51p2dn4pf1k6hVJS+sIazYm8U/mJ6AmhXC1dh
8xF/1JUfLbJZhUXvME85Y5SZXlGxYoraOwx6ZHqs4QKBgQD4cfCvTAc3yWszYGo+
zavOWK23WwKR/mQstK1NCjTPDhHlFU0JYyT4KCNiElVIqJ4kpttk9JxqUBrrH9Eo
TFVDmnrFZC6tqpZdgF+A+oJxMc/SVfh85KPN3IWb+2WtzHy8tTQW1Rb3TD7HuKo5
VkO/DTX1L//+yKGkMV98KR+dbQKBgQDUQFrvC7JAfXSVUhJWHRyZmeoYYB8eMrAW
kR0XaJhdqmisxWKFaGWFArY2MEbB8rTa3EyxS9RKfMa8GaLNPoqHTZXKzTe4JRco
jypO3VayDavk5rN8TQ+kgSkM4s2JiiBwg3f+ICwEPObvbagU/+pimGbR+P/kW0mq
6g76bGr0awKBgQDexOvXgwiF0Sk6bB1YKvr+jy1U11o6piwUmf06swgfELKjArKM
1EV17ier7FxkRi1nF+ZpY5xNB37bjS/yPl/FumKTU/0241rohA8ei4EjFlMOet/Q
vQLTuARllMnbSRwf6SrHvlJVdBxm4QJhXyRnzuSu8VdNkYC+xTalEgqzEQKBgQCW
hCi4OlgnCZCCT5g3Px/IAXET5h5LIPDkn/W8Yu0iBzWBx9wM9TKA96JVnTigU0hT
qEQuurKKPCAGxjtAR2ifeLKQBaXMzWi114jOMoJHdBCBG+UOcet04i9FNxVAwxYs
E98k9JWiT7oI8n9unOkPEDpiDq0QuHfuX1tN1VKnjwKBgDNSEXqmRHew/C0GSaf5
fQL612f4I8zU9BCZeXASHgCjYkIo9+d1Amz0HFbYYuwACK5l9GxEO7TsBv8S3CcM
HZf48zF7B158wdSXno1Rd1vIZoHkDZYlWxjBAk60LZLzggiYnpNpL/JJh+SI/CYz
K+g1U8zsBcMm15Hf+bJnIr+A
-----END PRIVATE KEY-----
''';
    final rsaKey = keyFromString(rsaPrivatePem);

    String sign(String signingInput, RSAPrivateKey rsaPrivateKey) {
      final jwsSignature = new JwsSignature.create(signingInput,
          JsonWebAlgorithm.RS256, new JwaSignatureContext(null,
              rsaKey: rsaPrivateKey));
      return jwsSignature.encode();
    }

    test('simple', () {
      expect(sign('eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.'
                  'eyJpYXQiOjEzOTQxNjYxODcsImV4cCI6MTM5NDE2NjM2NywiaXNzIjoiamly'
                  'YTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJzdWIi'
                  'OiJhZG1pbiIsImF1ZCI6ImZvb2JhciJ9', rsaKey),
                  equals('YUU-mhNuoVHti6ZPA5WcNVxBk_Y5m2grTSW1Biea0p9IcWao7QplG4ZMcnNCRW_2uYgENakUVvKFF7dSR0srt435OCznJCHgefsAAtSwKgrTZetThBsrc9NBxys-C0bp-u6UpUgbNUnZa-JH7_VElkdTsnqgvtCGo3xGtTeuSoPKQMu7aE7eMS2qof4QX-H0Ym1zrC4rWKf9sO4gdOyh9CmoWYHwkPrlc3IMwsm-1yxOUcNZvPRy63-hq7bsKZKc_MvGjjk7zpBO8K6PRWLiHmi7hilQKMw8iGskAtj7OWp_YidvBbem5TfM8BQxncGbtXySn6ygdP6M9DuJgxWA8w'));
    });
  });
}
