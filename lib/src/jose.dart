part of jwt;

/**
 * Base class for objects defined in the Jose specs that are strings made up of
 * base64 encoded [segments]. i.e. when encoded they are of the form 
 * `<base 64 encoded header>.<base64 encoded payload>.<another base64 encoded segment>`
 *  
 * At minimum they have a [header] and a [payload] as the first two segments.
 */
abstract class _JoseObject<H extends _JoseHeader, P extends _JosePayload> {
  final H header;
  final P payload;
  Iterable<Base64EncodedData> get segments;
  
  /**
   * Returns the encoded form of the object 
   */
  String encode() => _encodeSegmentsToString(segments.map((s) => s.encodedBytes));
  
  _JoseObject(this.header, this.payload);
}

/**
 * Represents some data that is base64 encoded
 */
abstract class Base64EncodedData {
  Iterable<int> get encodedBytes;
  
  String decode() => _bytesToBase64(encodedBytes);
}

abstract class Base64EncodedJson extends Base64EncodedData {
  Map toJson();
  
  @override
  Iterable<int> get encodedBytes => JSON.encode(toJson()).codeUnits;
}


abstract class _JoseHeader extends Base64EncodedJson {  
}

abstract class _JosePayload extends Base64EncodedJson {  
}

String _encodeJsonSegmentsToString(Iterable<Map> jsonSegs, 
                                   { bool stringPadding: true }) { 
  return _encodeSegmentsToString(jsonSegs.map((m) => JSON.encode(m).codeUnits),
                            stringPadding: stringPadding);
}

String _encodeSegmentsToString(Iterable<Iterable<int>> segments, 
                               { bool stringPadding: true }) {
  return _encodeSegments(segments, stringPadding: stringPadding).join('.');
}

Iterable<String> _encodeSegments(Iterable<Iterable<int>> segments, 
    { bool stringPadding: true }) {
  return segments.map((s) => _bytesToBase64(s, stringPadding: stringPadding));
}

String _bytesToBase64(Iterable<int> bytes, { bool stringPadding: true }) { 
  return _unpadIfRequired(CryptoUtils.bytesToBase64(bytes, urlSafe: true), 
        stringPadding: stringPadding);
}

Iterable<Iterable<int>> _decodeSegmentString(String base64EncodedSegmentString) =>
    _decodeSegments(base64EncodedSegmentString.split('.'));


Iterable<Iterable<int>> _decodeSegments(Iterable<String> segments) =>
    segments.map((s) => CryptoUtils.base64StringToBytes(_padIfRequired(s)));
  
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

DateTime _decodeIntDate(int secondsSinceEpoch) => 
    new DateTime.fromMillisecondsSinceEpoch(secondsSinceEpoch * 1000);

int _encodeIntDate(DateTime dateTime) =>
    dateTime.millisecondsSinceEpoch ~/ 1000;

// TODO: dynamic until dart supports generics on functions
dynamic checkNotNull(dynamic o, [String fieldName = "argument"]) {
  if (o == null) 
    throw new ArgumentError("$fieldName cannot be null");
  
  return o;
}