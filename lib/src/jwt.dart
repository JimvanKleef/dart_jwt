part of jwt;

typedef JwtClaimSet ClaimSetParser(Map json);

JwtClaimSet _defaultClaimSetParser(Map json) => new JwtClaimSet.fromJson(json);

abstract class Jwt<T extends JwtClaimSet> {
  T get claimSet;
  
  factory Jwt.decode(String jwtToken, 
      { JwsValidationContext validationContext, 
        ClaimSetParser claimSetParser: _defaultClaimSetParser }) {
    // TODO: figure out if the jwt is in a jws or jwe structure. Assuming jws for now
    return new _JwtInJws.decode(jwtToken, validationContext, claimSetParser);
  }
  
  factory Jwt.jws(T claimSet, JwaSignatureContext signatureContext) {
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

//class MutableJwt implements Jwt {
//  JwtClaimSet claimSet;
//}

class _JwtInJws<T extends JwtClaimSet> extends Jws<T> implements Jwt {
  T get claimSet => payload;
  
  _JwtInJws._internal(JwsHeader header, T claimSet, JwsSignature signature, 
      String signingInput) 
    : super._internal(header, claimSet, signature, signingInput);

  // TODO hard to factor out into JWS ctr but largely common across JWS impls
  factory _JwtInJws.decode(String jwtToken, JwsValidationContext validationContext, 
      ClaimSetParser claimSetParser) {
    final Iterable<Iterable<int>> decodedSegments = _decodeSegmentString(jwtToken);
    if (decodedSegments.length < 3)
      throw new ArgumentError("JWS string must be in form Header.Payload.Signature.\n$jwtToken\nis invalid");
    
    Map extractJson(int index) {
      return JSON.decode(new String.fromCharCodes(decodedSegments.elementAt(index)));
    }
    
    final JwsHeader header = new JwsHeader.fromJson(extractJson(0));
    if (header.type != JwsType.JWT) {
      throw new ArgumentError('Unsupported Jws type ${header.type}');
    }
    final T claimSet = claimSetParser(extractJson(1));
    final JwsSignature signature = new JwsSignature(decodedSegments.elementAt(2));
    final signingInput = jwtToken.substring(0,jwtToken.lastIndexOf('.'));
    final Jwt jwt = new _JwtInJws._internal(header, claimSet, signature, signingInput);
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
    final String signingInput = _JoseObject.encodeSegments([header, claimSet]);

    final JwsSignature signature = 
        new JwsSignature.create(signingInput, header.algorithm, signatureContext);
    
    return new _JwtInJws._internal(header, claimSet, signature, signingInput);
  }

  Set<ConstraintViolation> validate(JwtValidationContext validationContext) {
    final violations = super.validate(validationContext);
    return violations..addAll(claimSet.validate(validationContext.claimSetValidationContext));
  }
}

class JwtClaimSetValidationContext {
  final Duration expiryTolerance;
  
  const JwtClaimSetValidationContext( 
      { this.expiryTolerance: const Duration(seconds: 30) } );
}


class JwtClaimSet extends _JosePayload with _JwtClaimSetMixin {
  final String issuer;
  final String subject;
  final DateTime expiry;
  final DateTime issuedAt;
  
  JwtClaimSet(this.issuer, this.subject, this.expiry, this.issuedAt);
  
  JwtClaimSet.fromJson(Map json)
      : issuer = json['iss'],
        subject = json['sub'],
        expiry = _decodeIntDate(json['exp']),
        issuedAt = _decodeIntDate(json['iat']);

}

class MutableJwtClaimSet extends _JosePayload with _JwtClaimSetMixin 
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
      'iat' : _encodeIntDate(issuedAt),
      'exp' : _encodeIntDate(expiry),
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
          'JWT expired. Expiry ($expiry) is more than tolerance (${validationContext.expiryTolerance}) before now ($now)'));
    }
    
    return new Set.identity();
    
    // TODO: could support issuer and subject validation (by passing in lookup functions in context)
    // but may leave that to clients 
  }
}