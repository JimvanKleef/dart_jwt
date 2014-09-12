library jwt.jws;
 
import 'jose.dart';
import 'jwa.dart';
import 'validation_constraint.dart';
import 'dart:convert';
import 'util.dart';

typedef JosePayload PayloadParser(Map json);

/**
 * Represents a [JSON Web Signature](http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-24).
 * 
 * A Jws has a [header] that describes the [JsonWebAlgorithm] used to generate
 * the [signature] 
 */
abstract class JsonWebSignature<P extends JosePayload> extends JoseObject<JwsHeader, P> {
  final JwsSignature signature;
  final String _signingInput;
  
  Iterable<Base64EncodedData> get segments => [header, payload, signature];


  JsonWebSignature(JwsHeader header, P payload, this.signature, this._signingInput)
      : super(header, payload);

  Set<ConstraintViolation> validate(JwsValidationContext validationContext) {
    return validateSignature(validationContext)
        ..addAll(validatePayload(validationContext));
  }
  
  Set<ConstraintViolation> validateSignature(
      JwsValidationContext validationContext) {
    
    return signature.validate(_signingInput, header.algorithm,
              validationContext.signatureContext);
  }
  
  Set<ConstraintViolation> validatePayload(
      JwsValidationContext validationContext);

}

/// A header for a [JsonWebSignature] defining the [type] of JWS object and
/// [algorithm] used in the signature
class JwsHeader extends JoseHeader {
  final JwsType type;
  final JsonWebAlgorithm algorithm;

  JwsHeader(this.type, this.algorithm);


  JwsHeader.fromJson(Map json): this(JwsType.lookup(json['typ']),
      JsonWebAlgorithm.lookup(json['alg']));

  JwsHeader.decode(String base64String) :
    this.fromJson(Base64EncodedJson.decodeToJson(base64String));

  Map toJson() {
    return {
      'alg': algorithm.name,
      'typ': type.name
    };
  }

  String toString() => 'JwsHeader[type=$type, algorithm=$algorithm]';

  @override
  Iterable<int> get decodedBytes => JSON.encode(toJson()).codeUnits;
}

/// Encapsulates the actual signature for a [JsonWebSignature]
class JwsSignature extends Base64EncodedData {
  final List<int> signatureBytes;

  JwsSignature(this.signatureBytes);

  JwsSignature.create(String signingInput, JsonWebAlgorithm
               algorithm, JwaSignatureContext signatureContext) 
      : signatureBytes = algorithm.sign(signingInput, signatureContext);

  JwsSignature.decode(String base64String)
      : this(Base64EncodedData.decodeToBytes(base64String));
  
  Set<ConstraintViolation> validate(String signingInput, JsonWebAlgorithm
      algorithm, JwaSignatureContext signatureContext) {

    List<int> result = algorithm.sign(signingInput, signatureContext);
    
    return _signaturesMatch(result) ? new Set.identity() : 
      (new Set()..add(new ConstraintViolation('signatures do not match. ' + 
          'Received: ${bytesToBase64(signatureBytes)} vs ' + 
          'Calculated: ${bytesToBase64(result)}')));
  }

  bool _signaturesMatch(List<int> result) {
    return signatureBytes.length == result.length && new List.generate(
        signatureBytes.length, (i) => i).every((i) => signatureBytes[i] == result[i]);
  }

  @override
  Iterable<int> get decodedBytes => signatureBytes;
}

/// The type of [JsonWebSignature] object
class JwsType {
  final String name;

  const JwsType._internal(this.name);

  static JwsType lookup(String name) {
    return checkNotNull(_supportedTypes[name]);
  }

  static const JwsType JWT = const JwsType._internal('JWT');

  static Map<String, JwsType> _supportedTypes = {
    null: JWT,
    'JWT': JWT
  };

  String toString() => '$name';
}

class JwsValidationContext {
  final JwaSignatureContext signatureContext;

  JwsValidationContext(this.signatureContext);
}


