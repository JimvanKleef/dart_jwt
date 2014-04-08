part of jwt;

typedef JosePayload PayloadParser(Map json);

// TODO: no idea what this should really look like
class JwsValidationContext {
  final JwaSignatureContext signatureContext;

  JwsValidationContext(this.signatureContext);
}


abstract class Jws<P extends JosePayload> extends JoseObject<JwsHeader, P> {
  final JwsSignature signature;
  final String signingInput;
  
  Iterable<Base64EncodedData> get segments => [header, payload, signature];


  Jws._internal(JwsHeader header, P payload, this.signature, this.signingInput)
      : super(header, payload);

  Set<ConstraintViolation> validate(JwsValidationContext validationContext) {
    // TODO: validate exp etc too
    return signature.validate(signingInput, header.algorithm, 
        validationContext.signatureContext);
  }

}

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

//abstract class JwsPayload {
//}

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
          'Received: ${_bytesToBase64(signatureBytes)} vs ' + 
          'Calculated: ${_bytesToBase64(result)}')));
  }

  bool _signaturesMatch(List<int> result) {
    return signatureBytes.length == result.length && new List.generate(
        signatureBytes.length, (i) => i).every((i) => signatureBytes[i] == result[i]);
  }

  @override
  Iterable<int> get decodedBytes => signatureBytes;
}

class JwsType {
  final String name;

  const JwsType._internal(this.name);

  static JwsType lookup(String name) {
    return checkNotNull(_supportedTypes[name]);
  }

  static const JwsType JWT = const JwsType._internal('JWT');

  static Map<String, JwsType> _supportedTypes = {
    'JWT': JWT
  };

  String toString() => '$name';
}
