library jwt.jose;
 
import 'package:crypto/crypto.dart';
import 'dart:convert';


/**
 * Base class for objects defined in the Jose specs that are strings made up of
 * base64 encoded [segments]. i.e. when encoded they are of the form 
 * `<base 64 encoded header>.<base64 encoded payload>.<another base64 encoded segment>`
 *  
 * At minimum they have a [header] and a [payload] as the first two segments.
 */
abstract class JoseObject<H extends JoseHeader, P extends JosePayload> {
  final H header;
  final P payload;
  Iterable<Base64EncodedData> get segments;
  
  /**
   * Returns the encoded form of the object 
   */
  String encode() => encodeSegments(segments); 
  
  JoseObject(this.header, this.payload);
  
  static String encodeSegments(Iterable<Base64EncodedData> segments) => 
      segments.map((s) => s.encode()).join('.'); 
}

/**
 * Represents some data that may be base64 encoded. It provides a decoded form
 * as bytes in [decodedBytes] and an encoded form via [encode]
 */
abstract class Base64EncodedData {
  /// The decoded (or raw) form of the data as bytes
  Iterable<int> get decodedBytes;
  
  /// The base64 encoded form of the data
  String encode() => bytesToBase64(decodedBytes);
  
  static Iterable<int> decodeToBytes(String base64String) 
    => CryptoUtils.base64StringToBytes(_padIfRequired(base64String));

  static String decodeToString(String base64String) 
    => new String.fromCharCodes(decodeToBytes(base64String));
}

/**
 * Base64EncodedData that has a json form. The json form is available via
 * [toJson]
 */
abstract class Base64EncodedJson extends Base64EncodedData {
  Map toJson();
  
  @override
  Iterable<int> get decodedBytes => JSON.encode(toJson()).codeUnits;
  
  static Map decodeToJson(String base64String) 
    => JSON.decode(Base64EncodedData.decodeToString(base64String));

}

/**
 * Base class for a [JoseObject]'s header
 */
abstract class JoseHeader extends Base64EncodedJson {  
}

/**
 * Base class for a [JoseObject]'s payload
 */
abstract class JosePayload extends Base64EncodedJson {  
}

String bytesToBase64(Iterable<int> bytes, { bool stringPadding: true }) { 
  return _unpadIfRequired(CryptoUtils.bytesToBase64(bytes, urlSafe: true), 
        stringPadding: stringPadding);
}

String _padIfRequired(String s) {
  final int paddingAmount = s.length % 4;
  return (paddingAmount > 0) ?
    s.padRight(s.length + (4 - paddingAmount), '=') : s;
}

String _unpadIfRequired(String s, { bool stringPadding: true }) {
  if (!stringPadding || !s.endsWith('=')) {
    return s;
  }
  int cu = '='.codeUnits.first;
  int i = s.length - 1;
  for (; s.codeUnitAt(i) == cu; i--);
  return s.substring(0, i + 1);
}

DateTime decodeIntDate(int secondsSinceEpoch) => 
    new DateTime.fromMillisecondsSinceEpoch(secondsSinceEpoch * 1000);

int encodeIntDate(DateTime dateTime) =>
    dateTime.millisecondsSinceEpoch ~/ 1000;

// TODO: dynamic until dart supports generics on functions
dynamic checkNotNull(dynamic o, [String fieldName = "argument"]) {
  if (o == null) 
    throw new ArgumentError("$fieldName cannot be null");
  
  return o;
}