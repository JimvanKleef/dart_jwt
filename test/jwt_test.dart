library jwt.test;

import 'package:jwt/jwt.dart';
//import 'package:crypto/crypto.dart';

import 'package:unittest/unittest.dart';

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
  final String jwtStr = r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWRhMzA2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4IiwiaWF0IjoxMzk0MTY2MTg3fQ.bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc';

  group('[decode]', () {
//    String jwtStr = r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWRhMzA2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4IiwiaWF0IjoxMzk0MTY2MTg3fQ==.bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc=';
    
    /*
     * 1394176093476
     * 2014-03-07 15:26:07.000
{
    "exp": 1394166367,
    "sub": "admin",
    "iss": "jira:ae390d29-31b2-4c12-a719-9df64e3e92b7",
    "qsh": "eb4ec5f0980d01da306db89fa57dd163574667436dd720d5d9c5279c5b45f7a8",
    "iat": 1394166187
    
    
2014-03-07T02:05:55.725461+00:00 app[web.1]: Saved tenant details for jira:ae390d29-31b2-4c12-a719-9df64e3e92b7 to database
2014-03-07T02:05:55.725461+00:00 app[web.1]: { key: 'user-management-tester-AH1RD',
2014-03-07T02:05:55.725461+00:00 app[web.1]:   clientKey: 'jira:ae390d29-31b2-4c12-a719-9df64e3e92b7',
2014-03-07T02:05:55.725461+00:00 app[web.1]:   publicKey: 'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCIq0Npj3ssCxzstikotNaYNdAKiSA8in+NoSI91LN/+6Ul3HH3K9H1oPehUqTEeM+WHZabHdSRV4iq7SRJqdIINOZGBwpxjAuIXaOceDcly1L955jC9+J8Y299Gz0yfV7pMpHs9nkhy2bObe+H+5oP/27yYv+6QzviML/x5ydXwQIDAQAB',
2014-03-07T02:05:55.725461+00:00 app[web.1]:   sharedSecret: '3ab90b11-d7bd-4097-958f-01b7ac4e985f',
2014-03-07T02:05:55.725461+00:00 app[web.1]:   serverVersion: '6306',
2014-03-07T02:05:55.725461+00:00 app[web.1]:   pluginsVersion: '1.0.0.rc7-user-management',
2014-03-07T02:05:55.725461+00:00 app[web.1]:   baseUrl: 'https://connect-rc7-jira.jira-dev.com',
2014-03-07T02:05:55.725461+00:00 app[web.1]:   productType: 'jira',
2014-03-07T02:05:55.725461+00:00 app[web.1]:   description: 'Atlassian JIRA at https://connect-rc7-jira.jira-dev.com',
2014-03-07T02:05:55.725717+00:00 app[web.1]:   eventType: 'installed' }
    
}     
     */
    Jwt jwt() => new Jwt.decode(jwtStr);
    JwtClaimSet claimSet() => jwt().claimSet;
    
    group('[header]', () {
      test('TODO', () {
        // the header is not currently in Jwt. Maybe it should be after abstracting across
        // JWS and JWE
      });
    });
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
  //https://addon-user-tester-aholmgren.herokuapp.com/jira/issue-tester?tz=Australia%2FSydney&loc=en-US&user_id=admin&user_key=admin&xdm_e=https%3A%2F%2Fconnect-rc7-jira.jira-dev.com&xdm_c=channel-issue-tester-jira--ah1-rd&cp=&lic=none&jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWRhMzA2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4IiwiaWF0IjoxMzk0MTY2MTg3fQ.bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc
  
  group('[encode]', () {
    final String jwtStr = r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjEzOTQxNjYzNjcsInN1YiI6ImFkbWluIiwiaXNzIjoiamlyYTphZTM5MGQyOS0zMWIyLTRjMTItYTcxOS05ZGY2NGUzZTkyYjciLCJxc2giOiJlYjRlYzVmMDk4MGQwMWRhMzA2ZGI4OWZhNTdkZDE2MzU3NDY2NzQzNmRkNzIwZDVkOWM1Mjc5YzViNDVmN2E4IiwiaWF0IjoxMzk0MTY2MTg3fQ.bR8Z0MIguOg6xgHiav0quun8kTqXzNUKMKym-PFjZvc';

    final claimSet = new MutableJwtClaimSet()
      ..issuer=issuer
      ..subject=subject
      ..expiry=expiry
      ..issuedAt=issuedAt
      ..toImmutable();
    
    Jwt jwt() => new Jwt.jws(claimSet, signatureContext);
    String encode() => jwt().encode();
    Jwt parseEncoded() => new Jwt.decode(encode(), validationContext: validationContext);
    JwtClaimSet roundtripClaimSet() => parseEncoded().claimSet;
    
    
    // need qsh etc for this to parse. Also order dependent in json so not useful
    skip_test('encodes correctly', () {
      expect(jwt().encode(), equals(jwtStr));
    });
    
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
      ..expiry=new DateTime.now().subtract(new Duration(seconds: secondsBeforeNow))
      ..issuedAt=issuedAt
      ..toImmutable();
    
    Set<ConstraintViolation> violations(int secondsBeforeNow) => claimSet(secondsBeforeNow).validate(const JwtClaimSetValidationContext());
    
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

