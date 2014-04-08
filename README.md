# JSON Web Token (JWT) for Dart

## Introduction

Provides an implementation of [JSON Web Token](http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-19) standard.
    
## Using
### Basic Usage

**Decoding**

To decode a JWT string

```
JsonWebToken jwt = new JsonWebToken.decode(jwtStr);
```
**Validating**

To validate the decoded jwt

```
Set<ConstraintViolation> violations = jwt.validate(new JwtClaimSetValidationContext());
```

If the jwt is valid this will return an empty set. Otherwise the set will contain all the things that were invalid.

Note you can also validate as you decode

```
JsonWebToken jwt = new JsonWebToken.decode(jwtStr);

```


## Limitaions

Currently this supports enough of the JWT spec that was needed for a project. Specifically it only implements:

* JWS (no JWE support)
* HS256 for the JWS signature.

## Issues

* Validation needs work. The intention is to piggy back off a constraint validation library (similar to Java Bean Validation) but I haven't written that yet.
