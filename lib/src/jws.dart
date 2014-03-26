part of jwt;

typedef _JosePayload PayloadParser(Map json);

// TODO: no idea what this should really look like
class JwsValidationContext {
  final JwaSignatureContext signatureContext;

  JwsValidationContext(this.signatureContext);
}


abstract class Jws<P extends _JosePayload> extends _JoseObject<JwsHeader, P> {
  final JwsSignature signature;
  final String signingInput;
  
  Iterable<Base64EncodedData> get segments => [header, payload, signature];


  Jws._internal(JwsHeader header, P payload, this.signature, this.signingInput)
      : super(header, payload);

  //  Jws._internal2(JwsHeader header(), P payload(), JwsSignature signature()) : this(header(), payload());

  //  Jws.parse(String jwsString, PayloadParser payloadParser)
  //
  //  {
  //    final Iterable<Iterable<int>> decodedSegments = _decodeSegmentString(jwsString);
  //    if (decodedSegments.length < 3)
  //      throw new ArgumentError("JWS string must be in form Header.Payload.Signature.\n$jwsString\nis incalid");
  //
  //    Map toJson(int index) {
  //      final String jsonStr = new String.fromCharCodes(decodedSegments.elementAt(index));
  //      return JSON.decode(jsonStr);
  //    }
  //
  //    final JwsHeader header = new JwsHeader.fromJson(toJson(0));
  //    final P payload = payloadParser(toJson(1));
  //    final JwsSignature signature = new JwsSignature.fromJson(toJson(2));
  //    return new Jws._internal(header, payload, signature);
  //  }

  Set<ConstraintViolation> validate(JwsValidationContext validationContext) {
    // TODO: validate exp etc too
    return signature.validate(signingInput, header.algorithm, 
        validationContext.signatureContext);
  }

}

class JwsHeader extends _JoseHeader {
  final JwsType type;
  final JsonWebAlgorithm algorithm;

  JwsHeader(this.type, this.algorithm);


  JwsHeader.fromJson(Map json): this(JwsType.lookup(json['typ']),
      JsonWebAlgorithm.lookup(json['alg']));

  Map toJson() {
    return {
      'alg': algorithm.name,
      'typ': type.name
    };
  }

  String toString() => 'JwsHeader[type=$type, algorithm=$algorithm]';

  @override
  Iterable<int> get encodedBytes => JSON.encode(toJson()).codeUnits;
}

//abstract class JwsPayload {
//}

class JwsSignature extends Base64EncodedData {
  final List<int> signatureBytes;

  JwsSignature(this.signatureBytes);

  JwsSignature.create(String signingInput, JsonWebAlgorithm
               algorithm, JwaSignatureContext signatureContext) 
      : signatureBytes = algorithm.sign(signingInput, signatureContext);
  
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
  Iterable<int> get encodedBytes => signatureBytes;
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
