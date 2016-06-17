[![Build Status](https://travis-ci.org/jwtk/jjwt.svg?branch=master)](https://travis-ci.org/jwtk/jjwt)
[![Coverage Status](https://coveralls.io/repos/jwtk/jjwt/badge.svg?branch=master)](https://coveralls.io/r/jwtk/jjwt?branch=master)

# Java JWT: JSON Web Token for Java and Android

JJWT aims to be the easiest to use and understand library for creating and verifying JSON Web Tokens (JWTs) on the JVM.

JJWT is a 'clean room' implementation based solely on the [JWT](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-25), [JWS](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31), [JWE](https://tools.ietf.org/html/draft-ietf-jose-json-web-encryption-31) and [JWA](https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-31) RFC draft specifications.

## Installation

Use your favorite Maven-compatible build tool to pull the dependency (and its transitive dependencies) from Maven Central:

Maven:

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt</artifactId>
    <version>0.6.0</version>
</dependency>
```

Gradle:

```groovy
dependencies {
    compile 'io.jsonwebtoken:jjwt:0.6.0'
}
```

Note: JJWT depends on Jackson 2.x.  If you're already using an older version of Jackson in your app, [read this](#olderJackson)

## Usage

Most complexity is hidden behind a convenient and readable builder-based [fluent interface](http://en.wikipedia.org/wiki/Fluent_interface), great for relying on IDE auto-completion to write code quickly.  Here's an example:

```java
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.crypto.MacProvider;
import java.security.Key;

// We need a signing key, so we'll create one just for this example. Usually
// the key would be read from your application configuration instead.
Key key = MacProvider.generateKey();

String s = Jwts.builder().setSubject("Joe").signWith(SignatureAlgorithm.HS512, key).compact();
```

How easy was that!?

Now let's verify the JWT (you should always discard JWTs that don't match an expected signature):

```java
assert Jwts.parser().setSigningKey(key).parseClaimsJws(s).getBody().getSubject().equals("Joe");
```

You have to love one-line code snippets!

But what if signature validation failed?  You can catch `SignatureException` and react accordingly:

```java
try {

    Jwts.parser().setSigningKey(key).parseClaimsJws(compactJwt);

    //OK, we can trust this JWT

} catch (SignatureException e) {

    //don't trust the JWT!
}
```

## Supported Features

* Creating and parsing plaintext compact JWTs

* Creating, parsing and verifying digitally signed compact JWTs (aka JWSs) with all standard JWS algorithms:
    * HS256: HMAC using SHA-256
    * HS384: HMAC using SHA-384
    * HS512: HMAC using SHA-512
    * RS256: RSASSA-PKCS-v1_5 using SHA-256
    * RS384: RSASSA-PKCS-v1_5 using SHA-384
    * RS512: RSASSA-PKCS-v1_5 using SHA-512
    * PS256: RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    * PS384: RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    * PS512: RSASSA-PSS using SHA-512 and MGF1 with SHA-512
    * ES256: ECDSA using P-256 and SHA-256
    * ES384: ECDSA using P-384 and SHA-384
    * ES512: ECDSA using P-512 and SHA-512

## Currently Unsupported Features

* [Non-compact](https://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#section-7.2) serialization and parsing.
* JWE (Encryption for JWT)

These feature sets will be implemented in a future release when possible.  Community contributions are welcome!

