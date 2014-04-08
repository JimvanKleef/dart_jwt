library jwt.jwt.test;

import 'package:unittest/unittest.dart';
import 'package:dart_jwt/src/jwa.dart';
import 'package:dart_jwt/src/jwt.dart';
import 'package:dart_jwt/src/validation_constraint.dart';

void main()  {
  final String sharedSecret = '3ab90b11-d7bd-4097-958f-01b7ac4e985f';
  final String issuer = 'jira:ae390d29-31b2-4c12-a719-9df64e3e92b7';
  final String subject = 'admin';
  final DateTime expiry = DateTime.parse('2014-03-07 15:26:07.000');
  final DateTime issuedAt = DateTime.parse('2014-03-07 15:23:07.000');
  final JwaSignatureContext signatureContext = new JwaSignatureContext(sharedSecret);
  final claimSetValidationContext = new JwtClaimSetValidationContext(
      expiryTolerance: const Duration(days: 365*1000));
  final JwtValidationContext validationContext = new JwtValidationContext(
      signatureContext, claimSetValidationContext);
  final String jwtStr = r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
      'eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyOS0'
      'zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWRhMz'
      'A2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4IiwiaWF0I'
      'joxMzk0MTY2MTg3fQ.bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc';

  group('[decode]', () {

    JsonWebToken jwt() => new JsonWebToken.decode(jwtStr);
    JwtClaimSet claimSet() => jwt().claimSet;
    
    group('[claimset]', () {
      test('issuer parses', () {
        expect(claimSet().issuer, equals(issuer));
      });
      test('subject parses', () {
        expect(claimSet().subject, equals(subject));
      });
      test('expiry parses', () {
        expect(claimSet().expiry, equals(expiry));
      });
      test('issuedAt parses', () {
        expect(claimSet().issuedAt, equals(issuedAt));
      });
    });
    group('[signature]', () {
      test('validates successfully with correct shared secret', () {
        Set<ConstraintViolation> violations = jwt().validate(validationContext);
        expect(violations, isEmpty);        
      });
    });
  });
  
  group('[encode]', () {
    final String jwtStr = r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
        'eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyO'
        'S0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWR'
        'hMzA2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4Iiwia'
        'WF0IjoxMzk0MTY2MTg3fQ.bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc';

    final claimSet = (new MutableJwtClaimSet()
      ..issuer=issuer
      ..subject=subject
      ..expiry=expiry
      ..issuedAt=issuedAt)
      .toImmutable();
    
    JsonWebToken jwt() => new JsonWebToken.jws(claimSet, signatureContext);
    String encode() => jwt().encode();
    JsonWebToken parseEncoded() => new JsonWebToken.decode(encode(), 
        validationContext: validationContext);
    JwtClaimSet roundtripClaimSet() => parseEncoded().claimSet;
    
    
    group('[roundtrip]', () {
      test('issuer matches', () {
        expect(roundtripClaimSet().issuer, equals(issuer));
      });
      test('subject matches', () {
        expect(roundtripClaimSet().subject, equals(subject));
      });
      test('expiry matches', () {
        expect(roundtripClaimSet().expiry, equals(expiry));
      });
      test('issuedAt matches', () {
        expect(roundtripClaimSet().issuedAt, equals(issuedAt));
      });
    });
  });
  
  group('[validation]', () {

    JwtClaimSet claimSet(int secondsBeforeNow) => new MutableJwtClaimSet()
      ..issuer=issuer
      ..subject=subject
      ..expiry=new DateTime.now().subtract(
          new Duration(seconds: secondsBeforeNow))
      ..issuedAt=issuedAt
      ..toImmutable();
    
    Set<ConstraintViolation> violations(int secondsBeforeNow) => 
        claimSet(secondsBeforeNow).validate(const JwtClaimSetValidationContext());
    
    group('[expiry]', () {
      test('fails validation if more than tolerance past expiry', () {
        expect(violations(31), isNot(isEmpty));
      });
    
      test('passes validation if no more than tolerance past expiry', () {
        expect(violations(30), isEmpty);
      });
    
    });
  });
}

