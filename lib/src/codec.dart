library jwt.codec;

import 'dart:convert';
import 'package:dart_jwt/src/jwt_claimset.dart';
import 'package:dart_jwt/src/jwt.dart';
import 'package:dart_jwt/src/jws.dart';

typedef JsonWebToken<CS> JwtTokenDecoder<CS extends JwtClaimSet>(
    String jwtToken, {JwsValidationContext validationContext});

class JwtCodec<CS extends JwtClaimSet> extends Codec<JsonWebToken<CS>, String> {
  final Converter<JsonWebToken<CS>, String> encoder = new JwtEncoder<CS>();
  final Converter<String, JsonWebToken<CS>> decoder;

  JwtCodec(this.decoder);

  JwtCodec.simple(JwtTokenDecoder<CS> decoder,
      {JwsValidationContextFactory contextFactory})
      : this(new JwtDecoder(decoder, contextFactory));
}

class JwtDecoder<CS extends JwtClaimSet>
    extends Converter<String, JsonWebToken<CS>> {
  final JwtTokenDecoder<CS> decoder;
  final JwsValidationContextFactory contextFactory;

  JwtDecoder(this.decoder, this.contextFactory);

  @override
  JsonWebToken<CS> convert(String input) => contextFactory != null
      ? decoder(input, validationContext: contextFactory())
      : decoder(input);
}

class JwtEncoder<CS extends JwtClaimSet>
    extends Converter<JsonWebToken<CS>, String> {
  @override
  String convert(JsonWebToken<CS> input) => JSON.encode(input);
}
