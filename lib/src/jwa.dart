library jwt.jwa;
 
import 'jose.dart';
import 'package:crypto/crypto.dart';
import 'package:logging/logging.dart';

Logger _log = new Logger("jwt.jwa");

abstract class JsonWebAlgorithm {
  final String name;
  
  const JsonWebAlgorithm._internal(this.name);
  
  static JsonWebAlgorithm lookup(String name) {
    return checkNotNull(_supportedAlgorithms[name]);    
  }
  
  static const JsonWebAlgorithm HS256 = const _HS256JsonWebAlgorithm();
  
  static Map<String, JsonWebAlgorithm> _supportedAlgorithms = { 'HS256' : HS256 };
  
  String toString() => '$name';

  // TODO: This is not well thought out. Just cobbled together for now.
  // Not sure whether it's a good idea to have the algorithms sign.
  // Definitely should not take a JwsSignatureValidationContext. Maybe a JwaSigningContext
  // if that makes sense
  List<int> sign(String signingInput, JwaSignatureContext validationContext) {
    /*
     * TODO: ugly. Because I'm base 64 decoding the signature from the request I need
     * to reencode here. Better to avoid the decode in the first place 
     */
    final raw = _rawSign(signingInput, validationContext);
    final sig = CryptoUtils.bytesToBase64(raw, urlSafe: true);
    _log.finest('signature is $sig');
    return CryptoUtils.base64StringToBytes(sig);
  }
  
  List<int> _rawSign(String signingInput, JwaSignatureContext validationContext);
}

// TODO: no idea what this should really look like
class JwaSignatureContext {
  final String symmetricKey;
  JwaSignatureContext(this.symmetricKey);
}



class _HS256JsonWebAlgorithm extends JsonWebAlgorithm {
  
  const _HS256JsonWebAlgorithm() : super._internal('HS256');
  
  @override
  List<int> _rawSign(String signingInput, JwaSignatureContext signatureContext) {
    _log.finest('signingInput: $signingInput, sharedSecret: ${signatureContext.symmetricKey}');
    final hmac = new HMAC(new SHA256(), signatureContext.symmetricKey.codeUnits);
    hmac.add(signingInput.codeUnits);
    return hmac.digest;
  }
}