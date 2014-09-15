library jwt.jwa;
 
import 'util.dart';
import 'package:crypto/crypto.dart';
import 'package:logging/logging.dart';
import 'package:googleapis_auth/src/crypto/rsa_sign.dart';
import 'package:googleapis_auth/src/crypto/rsa.dart';

Logger _log = new Logger("jwt.jwa");

/**
 * Represents a [JSON Web Algorithm](http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-25)
 */
abstract class JsonWebAlgorithm {
  final String name;
  
  const JsonWebAlgorithm._internal(this.name);
  
  static JsonWebAlgorithm lookup(String name) {
    return checkNotNull(_supportedAlgorithms[name]);    
  }
  
  static const JsonWebAlgorithm HS256 = const _HS256JsonWebAlgorithm();
  static const JsonWebAlgorithm RS256 = const _RS256JsonWebAlgorithm();

  static Map<String, JsonWebAlgorithm> _supportedAlgorithms = {
    'HS256' : HS256,
    'RS256' : RS256
  };

  String toString() => '$name';

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

// TODO: This is very specific to what is needed for HS256. Will need to be
// generalised for other algorithms
class JwaSignatureContext {
  final String symmetricKey;
  final RSAPrivateKey rsaKey;
  JwaSignatureContext(this.symmetricKey, {this.rsaKey});
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

class _RS256JsonWebAlgorithm extends JsonWebAlgorithm {
  const _RS256JsonWebAlgorithm() : super._internal('RS256');

  @override
  List<int> _rawSign(String signingInput, JwaSignatureContext signatureContext) {
    final signer = new RS256Signer(signatureContext.rsaKey);
    return signer.sign(signingInput.codeUnits);
  }
}
