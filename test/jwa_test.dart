library jwt.jwa.test;


import 'package:unittest/unittest.dart';
import 'package:dart_jwt/src/jws.dart';
import 'package:dart_jwt/src/jwa.dart';

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
}