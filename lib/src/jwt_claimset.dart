library jwt.jwt_claimset;

import 'jose.dart';
import 'validation_constraint.dart';
import 'util.dart';

abstract class JwtClaimSet extends JosePayload {
  Set<ConstraintViolation> validate(
      JwtClaimSetValidationContext validationContext);
}

abstract class MapJwtClaimSet extends JwtClaimSet {
  final Map json;

  MapJwtClaimSet(this.json);
  MapJwtClaimSet.fromJson(this.json);

  Map toJson() => json;
}

class OpenIdJwtClaimSet extends JwtClaimSet {
  final String issuer;
  final List<String> audience;
  final String subject;
  final DateTime expiry;
  final DateTime issuedAt;

  OpenIdJwtClaimSet(
      this.issuer, this.subject, this.expiry, this.issuedAt, this.audience);

  OpenIdJwtClaimSet.build(
      {this.issuer, this.subject, this.expiry, this.issuedAt, this.audience});

  OpenIdJwtClaimSet.fromJson(Map json)
      : issuer = json['iss'],
        subject = json['sub'],
        expiry = decodeIntDate(json['exp']),
        issuedAt = decodeIntDate(json['iat']),
        audience = (json['aud'] is String ? [json['aud']] : json['aud']);

  OpenIdJwtClaimSet copy({String issuer, List<String> audience, String subject,
      DateTime expiry, DateTime issuedAt}) {
    return new OpenIdJwtClaimSet(issuer != null ? issuer : this.issuer,
        subject != null ? subject : this.subject,
        expiry != null ? expiry : this.expiry, issuedAt != null
            ? issuedAt
            : this.issuedAt, audience != null ? audience : this.audience);
  }

  Map toJson() => {
    'iat': encodeIntDate(issuedAt),
    'exp': encodeIntDate(expiry),
    'iss': issuer,
    'sub': subject,
    'aud': audience
  };

  String toString() => 'JwtClaimSet[issuer=$issuer]';

  Set<ConstraintViolation> validate(
      JwtClaimSetValidationContext validationContext) {
    final now = new DateTime.now();
    final diff = now.difference(expiry);
    if (diff > validationContext.expiryTolerance) {
      return new Set()
        ..add(new ConstraintViolation(
            'JWT expired. Expiry ($expiry) is more than tolerance '
            '(${validationContext.expiryTolerance}) before now ($now)'));
    }

    return new Set.identity();
  }
}

class JwtClaimSetValidationContext {
  final Duration expiryTolerance;

  const JwtClaimSetValidationContext(
      {this.expiryTolerance: const Duration(seconds: 30)});
}
