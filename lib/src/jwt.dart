library jwt.jwt;

import 'package:cipher/cipher.dart';
import 'jose.dart';
import 'jwa.dart';
import 'jws.dart';
import 'jwt_claimset.dart';
export 'jwt_claimset.dart';
import 'validation_constraint.dart';

/**
 * Represents a [JSON Web Token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-19)
 */
abstract class JsonWebToken<T extends JwtClaimSet> {
  /// The payload of a JWT is it's claim set
  T get claimSet;

  factory JsonWebToken.decode(String jwtToken,
      {JwsValidationContext validationContext,
      ClaimSetParser claimSetParser: _defaultClaimSetParser}) {
    // TODO: figure out if the jwt is in a jws or jwe structure. Assuming jws for now
    return new _JwtInJws.decode(jwtToken, validationContext, claimSetParser);
  }

  factory JsonWebToken.jws(T claimSet, JwaSignatureContext signatureContext) {
    return new _JwtInJws(claimSet, signatureContext);
  }

  // TODO: this doesn't make sense at this level but need to expose somehow.
  // What makes sense for jwe?
  Set<ConstraintViolation> validate(JwtValidationContext validationContext);

  /// Encodes the JWT into a string. The form differs depending on what
  /// container (JWS or JWE) houses the JWT.
  /// This is the form that is sent across the wire
  String encode();
}

/**
 * Represents a [JsonWebToken] that is encoded within a [JsonWebSignature]
 */
class _JwtInJws<T extends JwtClaimSet> extends JsonWebSignature<T>
    implements JsonWebToken {
  T get claimSet => payload;

  _JwtInJws._internal(
      JwsHeader header, T claimSet, JwsSignature signature, String signingInput)
      : super(header, claimSet, signature, signingInput);

  factory _JwtInJws.decode(String jwtToken,
      JwsValidationContext validationContext, ClaimSetParser claimSetParser) {
    final base64Segs = jwtToken.split('.');
    if (base64Segs.length != 3) throw new ArgumentError(
        "JWS string must be in form Header.Payload.Signature.\n"
        "$jwtToken\nis invalid");

    final header = new JwsHeader.decode(base64Segs.first);
    final claimSet =
        claimSetParser(Base64EncodedJson.decodeToJson(base64Segs.elementAt(1)));
    final signature = new JwsSignature.decode(base64Segs.elementAt(2));

    final signingInput = jwtToken.substring(0, jwtToken.lastIndexOf('.'));

    final JsonWebToken jwt =
        new _JwtInJws._internal(header, claimSet, signature, signingInput);

    if (validationContext != null) {
      final Set<ConstraintViolation> violations =
          jwt.validate(validationContext);
      if (violations.isNotEmpty) {
        throw new ConstraintViolations('jwt is invalid', violations);
      }
    }

    return jwt;
  }

  factory _JwtInJws(T claimSet, JwaSignatureContext signatureContext) {

    // TODO: need to add support for diff algorithms
    final JwsHeader header = new JwsHeader(JwsType.JWT, JsonWebAlgorithm.HS256);
    final String signingInput = JoseObject.encodeSegments([header, claimSet]);

    final JwsSignature signature = new JwsSignature.create(
        signingInput, header.algorithm, signatureContext);

    return new _JwtInJws._internal(header, claimSet, signature, signingInput);
  }

  @override
  Set<ConstraintViolation> validatePayload(
          JwtValidationContext validationContext) =>
      claimSet.validate(validationContext.claimSetValidationContext);
}

class JwtValidationContext extends JwsValidationContext {
  final JwtClaimSetValidationContext claimSetValidationContext;

  JwtValidationContext(
      JwaSignatureContext signatureContext, this.claimSetValidationContext)
      : super(signatureContext);

  JwtValidationContext.withSharedSecret(String sharedSecret) : this(
          new JwaSignatureContext(sharedSecret),
          new JwtClaimSetValidationContext());

  JwtValidationContext.withRsaPublicKey(RSAPublicKey rsaPublicKey) : this(
          new JwaSignatureContext.withKeys(rsaPublicKey: rsaPublicKey),
          new JwtClaimSetValidationContext());
}

typedef JwtClaimSet ClaimSetParser(Map json);

JwtClaimSet _defaultClaimSetParser(Map json) => new JwtClaimSet.fromJson(json);
