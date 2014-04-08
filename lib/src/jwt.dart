library jwt.jwt;

import 'jose.dart';
import 'jwa.dart';
import 'jws.dart';
import 'validation_constraint.dart';
import 'util.dart';

typedef JwtClaimSet ClaimSetParser(Map json);

JwtClaimSet _defaultClaimSetParser(Map json) => new JwtClaimSet.fromJson(json);

/**
 * Represents a [JSON Web Token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-19)
 */
abstract class JsonWebToken<T extends JwtClaimSet> {
  T get claimSet;
  
  factory JsonWebToken.decode(String jwtToken, 
      { JwsValidationContext validationContext, 
        ClaimSetParser claimSetParser: _defaultClaimSetParser }) {
    // TODO: figure out if the jwt is in a jws or jwe structure. Assuming jws for now
    return new _JwtInJws.decode(jwtToken, validationContext, claimSetParser);
  }
  
  factory JsonWebToken.jws(T claimSet, JwaSignatureContext signatureContext) {
    return new _JwtInJws(claimSet, signatureContext);
  }
  
  // TODO: this doesn't make sense at this level but need to expose somehow.
  // What makes sense for jwe?
  Set<ConstraintViolation> validate(JwtValidationContext validationContext) ;
  
  
  String encode();
}

class JwtValidationContext extends JwsValidationContext {
  final JwtClaimSetValidationContext claimSetValidationContext;
  
  JwtValidationContext(JwaSignatureContext signatureContext, 
      this.claimSetValidationContext) 
    : super(signatureContext);
  
  JwtValidationContext.withSharedSecret(String sharedSecret) 
      : this(new JwaSignatureContext(sharedSecret),
          new JwtClaimSetValidationContext());
}

class _JwtInJws<T extends JwtClaimSet> extends JsonWebSignature<T> implements JsonWebToken {
  T get claimSet => payload;
  
  _JwtInJws._internal(JwsHeader header, T claimSet, JwsSignature signature, 
      String signingInput) 
    : super(header, claimSet, signature, signingInput);

  // TODO hard to factor out into JWS ctr but largely common across JWS impls
  factory _JwtInJws.decode(String jwtToken, JwsValidationContext validationContext, 
      ClaimSetParser claimSetParser) {
    
    final base64Segs = jwtToken.split('.');
    if (base64Segs.length != 3)
      throw new ArgumentError(
          "JWS string must be in form Header.Payload.Signature.\n"
          "$jwtToken\nis invalid");
    
    final header = new JwsHeader.decode(base64Segs.first);
    final claimSet = claimSetParser(
        Base64EncodedJson.decodeToJson(base64Segs.elementAt(1)));
    final signature = new JwsSignature.decode(base64Segs.elementAt(2));
    
    final signingInput = jwtToken.substring(0,jwtToken.lastIndexOf('.'));
    
    final JsonWebToken jwt = new _JwtInJws._internal(header, claimSet, signature, 
        signingInput);
    
    if (validationContext != null) {
      final Set<ConstraintViolation> violations = jwt.validate(validationContext);
      if (violations.isNotEmpty) {
        // TODO: better exception type and better message
        throw new ArgumentError('jwt is invalid. $violations');
      }
    }
    
    return jwt;
  }

  factory _JwtInJws(T claimSet, JwaSignatureContext signatureContext) {
    
    // TODO: need to add support for diff algorithms
    final JwsHeader header = new JwsHeader(JwsType.JWT, JsonWebAlgorithm.HS256);
    final String signingInput = JoseObject.encodeSegments([header, claimSet]);

    final JwsSignature signature = 
        new JwsSignature.create(signingInput, header.algorithm, signatureContext);
    
    return new _JwtInJws._internal(header, claimSet, signature, signingInput);
  }

  @override
  Set<ConstraintViolation> validatePayload(JwtValidationContext validationContext) =>
    claimSet.validate(validationContext.claimSetValidationContext);
  
}

class JwtClaimSetValidationContext {
  final Duration expiryTolerance;
  
  const JwtClaimSetValidationContext( 
      { this.expiryTolerance: const Duration(seconds: 30) } );
}


class JwtClaimSet extends JosePayload with _JwtClaimSetMixin {
  final String issuer;
  final String subject;
  final DateTime expiry;
  final DateTime issuedAt;
  
  JwtClaimSet(this.issuer, this.subject, this.expiry, this.issuedAt);
  
  JwtClaimSet.fromJson(Map json)
      : issuer = json['iss'],
        subject = json['sub'],
        expiry = decodeIntDate(json['exp']),
        issuedAt = decodeIntDate(json['iat']);

}

class MutableJwtClaimSet extends JosePayload with _JwtClaimSetMixin 
    implements JwtClaimSet {
  String issuer;
  String subject;
  DateTime expiry;
  DateTime issuedAt;

  JwtClaimSet toImmutable() => 
      new JwtClaimSet(issuer, subject, expiry, issuedAt);

}

abstract class _JwtClaimSetMixin  {
  String get issuer;
  String get subject;
  DateTime get expiry;
  DateTime get issuedAt;

  Map toJson() {
    return {
      'iat' : encodeIntDate(issuedAt),
      'exp' : encodeIntDate(expiry),
      'iss' : issuer,
      'sub' : subject
    };
  }
  
  String toString() => 'JwtClaimSet[issuer=$issuer]';
    
  Set<ConstraintViolation> validate(JwtClaimSetValidationContext validationContext) {
    final now = new DateTime.now();
    final diff = now.difference(expiry);
    if (diff > validationContext.expiryTolerance) {
      return new Set()..add(new ConstraintViolation(
          'JWT expired. Expiry ($expiry) is more than tolerance '
          '(${validationContext.expiryTolerance}) before now ($now)'));
    }
    
    return new Set.identity();
  }
}