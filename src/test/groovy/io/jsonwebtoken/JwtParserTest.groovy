/*
 * Copyright (C) 2014 jsonwebtoken.io
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.jsonwebtoken

import io.jsonwebtoken.impl.TextCodec
import org.junit.Rule
import org.junit.Test
import org.junit.rules.ExpectedException

import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom

import static org.hamcrest.Matchers.is
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.core.StringStartsWith.startsWith

class JwtParserTest {
    @Rule
    public ExpectedException thrown = ExpectedException.none()

    private static final SecureRandom random = new SecureRandom() //doesn't need to be seeded - just testing

    protected static byte[] randomKey() {
        //create random signing key for testing:
        byte[] key = new byte[64]
        random.nextBytes(key)
        return key
    }

    @Test
    void testSetDuplicateSigningKeys() {

        byte[] keyBytes = randomKey()

        SecretKeySpec key = new SecretKeySpec(keyBytes, "HmacSHA256")

        String compact = Jwts.builder().setPayload('Hello World!').signWith(SignatureAlgorithm.HS256, keyBytes).compact()

        thrown.expect IllegalStateException
        thrown.expectMessage is('A key object and key bytes cannot both be specified. Choose either.')

        Jwts.parser().setSigningKey(keyBytes).setSigningKey(key).parse(compact)

    }

    @Test
    void testIsSignedWithNullArgument() {
        assertThat Jwts.parser().isSigned(null), is(false)
    }

    @Test
    void testIsSignedWithJunkArgument() {
        assertThat Jwts.parser().isSigned('hello'), is(false)
    }

    @Test
    void testParseWithJunkArgument() {

        String junkPayload = '{;aklsjd;fkajsd;fkjasd;lfkj}'

        String bad = TextCodec.BASE64.encode('{"alg":"none"}') + '.' +
                     TextCodec.BASE64.encode(junkPayload) + '.'

        thrown.expect MalformedJwtException
        thrown.expectMessage is('Unable to read JSON value: ' + junkPayload)

        Jwts.parser().parse(bad)
    }

    @Test
    void testParseJwsWithBadAlgHeader() {

        String badAlgorithmName = 'whatever'

        String header = "{\"alg\":\"$badAlgorithmName\"}"

        String payload = '{"subject":"Joe"}'

        String badSig = ";aklsjdf;kajsd;fkjas;dklfj"

        String bad = TextCodec.BASE64.encode(header) + '.' +
                TextCodec.BASE64.encode(payload) + '.' +
                TextCodec.BASE64.encode(badSig)

        thrown.expect SignatureException
        thrown.expectMessage is("Unsupported signature algorithm '$badAlgorithmName'".toString())

        Jwts.parser().setSigningKey(randomKey()).parse(bad)

    }

    @Test
    void testParseWithInvalidSignature() {

        String header = '{"alg":"HS256"}'

        String payload = '{"subject":"Joe"}'

        String badSig = ";aklsjdf;kajsd;fkjas;dklfj"

        String bad = TextCodec.BASE64.encode(header) + '.' +
                TextCodec.BASE64.encode(payload) + '.' +
                TextCodec.BASE64.encode(badSig)

        thrown.expect SignatureException
        thrown.expectMessage is('JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.')

        Jwts.parser().setSigningKey(randomKey()).parse(bad)

    }

    @Test
    void testParsePlaintextJwsWithIncorrectAlg() {

        String header = '{"alg":"none"}'

        String payload = '{"subject":"Joe"}'

        String badSig = ";aklsjdf;kajsd;fkjas;dklfj"

        String bad = TextCodec.BASE64.encode(header) + '.' +
                TextCodec.BASE64.encode(payload) + '.' +
                TextCodec.BASE64.encode(badSig)

        thrown.expect MalformedJwtException
        thrown.expectMessage is('JWT string has a digest/signature, but the header does not reference a valid signature algorithm.')

        Jwts.parser().setSigningKey(randomKey()).parse(bad)

    }

    @Test
    void testParseWithBase64EncodedSigningKey() {
        byte[] key = randomKey()
        String base64Encodedkey = TextCodec.BASE64.encode(key)
        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, base64Encodedkey).compact()

        assertThat Jwts.parser().isSigned(compact), is(true)

        Jwt<Header,String> jwt = Jwts.parser().setSigningKey(base64Encodedkey).parse(compact)

        assertThat jwt.body, is(payload)
    }

    @Test
    void testParseWithExpiredJwt() {

        Date exp = new Date(System.currentTimeMillis() - 1000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(exp).compact()

        thrown.expect ExpiredJwtException
        thrown.expectMessage startsWith('JWT expired at ')

        Jwts.parser().parse(compact)

    }

    @Test
    void testParseWithPrematureJwt() {

        Date nbf = new Date(System.currentTimeMillis() + 100000)

        String compact = Jwts.builder().setSubject('Joe').setNotBefore(nbf).compact()

        thrown.expect PrematureJwtException
        thrown.expectMessage startsWith('JWT must not be accepted before ')

        Jwts.parser().parse(compact)

    }

    // ========================================================================
    // parsePlaintextJwt tests
    // ========================================================================

    @Test
    void testParsePlaintextJwt() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).compact()

        Jwt<Header,String> jwt = Jwts.parser().parsePlaintextJwt(compact)

        assertThat jwt.getBody(), is(payload)
    }

    @Test
    void testParsePlaintextJwtWithClaimsJwt() {

        String compact = Jwts.builder().setSubject('Joe').compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Unsigned Claims JWTs are not supported.')

        Jwts.parser().parsePlaintextJwt(compact)

    }

    @Test
    void testParsePlaintextJwtWithPlaintextJws() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, randomKey()).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Signed JWSs are not supported.')

        Jwts.parser().parsePlaintextJws(compact)

    }

    @Test
    void testParsePlaintextJwtWithClaimsJws() {

        String compact = Jwts.builder().setSubject('Joe').signWith(SignatureAlgorithm.HS256, randomKey()).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Signed JWSs are not supported.')

        Jwts.parser().parsePlaintextJws(compact)

    }

    // ========================================================================
    // parseClaimsJwt tests
    // ========================================================================

    @Test
    void testParseClaimsJwt() {

        String subject = 'Joe'

        String compact = Jwts.builder().setSubject(subject).compact()

        Jwt<Header,Claims> jwt = Jwts.parser().parseClaimsJwt(compact)

        assertThat jwt.getBody().getSubject(), is(subject)
    }

    @Test
    void testParseClaimsJwtWithPlaintextJwt() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Unsigned plaintext JWTs are not supported.')

        Jwts.parser().parseClaimsJwt(compact)

    }

    @Test
    void testParseClaimsJwtWithPlaintextJws() {

        String payload = 'Hello world!'

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, randomKey()).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Signed JWSs are not supported.')

        Jwts.parser().parseClaimsJwt(compact)

    }

    @Test
    void testParseClaimsJwtWithClaimsJws() {

        String compact = Jwts.builder().setSubject('Joe').signWith(SignatureAlgorithm.HS256, randomKey()).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Signed JWSs are not supported.')

        Jwts.parser().parseClaimsJwt(compact)

    }

    @Test
    void testParseClaimsJwtWithExpiredJwt() {

        long nowMillis = System.currentTimeMillis()
        //some time in the past:
        Date exp = new Date(nowMillis - 1000)

        String compact = Jwts.builder().setSubject('Joe').setExpiration(exp).compact()

        thrown.expect ExpiredJwtException
        thrown.expectMessage startsWith('JWT expired at ')

        Jwts.parser().parseClaimsJwt(compact)

    }

    @Test
    void testParseClaimsJwtWithPrematureJwt() {

        Date nbf = new Date(System.currentTimeMillis() + 100000)

        String compact = Jwts.builder().setSubject('Joe').setNotBefore(nbf).compact()

        thrown.expect PrematureJwtException
        thrown.expectMessage startsWith('JWT must not be accepted before ')

        Jwts.parser().parseClaimsJwt(compact)

    }

    // ========================================================================
    // parsePlaintextJws tests
    // ========================================================================

    @Test
    void testParsePlaintextJws() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, key).compact()

        Jwt<Header,String> jwt = Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)

        assertThat jwt.getBody(), is(payload)
    }

    @Test
    void testParsePlaintextJwsWithPlaintextJwt() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Unsigned plaintext JWTs are not supported.')

        Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)

    }

    @Test
    void testParsePlaintextJwsWithClaimsJwt() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Unsigned Claims JWTs are not supported.')

        Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)

    }

    @Test
    void testParsePlaintextJwsWithClaimsJws() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Signed Claims JWSs are not supported.')

        Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)
    }

    // ========================================================================
    // parseClaimsJws tests
    // ========================================================================

    @Test
    void testParseClaimsJws() {

        String sub = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(sub).signWith(SignatureAlgorithm.HS256, key).compact()

        Jwt<Header,Claims> jwt = Jwts.parser().setSigningKey(key).parseClaimsJws(compact)

        assertThat jwt.getBody().getSubject(), is(sub)
    }

    @Test
    void testParseClaimsJwsWithExpiredJws() {

        String sub = 'Joe'

        byte[] key = randomKey()

        long nowMillis = System.currentTimeMillis()
        //some time in the past:
        Date exp = new Date(nowMillis - 1000)

        String compact = Jwts.builder().setSubject(sub).signWith(SignatureAlgorithm.HS256, key).setExpiration(exp).compact()

        thrown.expect ExpiredJwtException
        thrown.expectMessage startsWith('JWT expired at ')

        Jwts.parser().setSigningKey(key).parseClaimsJwt(compact)

    }

    @Test
    void testParseClaimsJwsWithPrematureJws() {

        String sub = 'Joe'

        byte[] key = randomKey()

        Date nbf = new Date(System.currentTimeMillis() + 100000)

        String compact = Jwts.builder().setSubject(sub).setNotBefore(nbf).signWith(SignatureAlgorithm.HS256, key).compact()

        thrown.expect PrematureJwtException
        thrown.expectMessage startsWith('JWT must not be accepted before ')

        Jwts.parser().setSigningKey(key).parseClaimsJws(compact)

    }

    @Test
    void testParseClaimsJwsWithPlaintextJwt() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Unsigned plaintext JWTs are not supported.')

        Jwts.parser().setSigningKey(key).parseClaimsJws(compact)

    }

    @Test
    void testParseClaimsJwsWithClaimsJwt() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Unsigned Claims JWTs are not supported.')

        Jwts.parser().setSigningKey(key).parseClaimsJws(compact)

    }

    @Test
    void testParseClaimsJwsWithPlaintextJws() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('Signed Claims JWSs are not supported.')

        Jwts.parser().setSigningKey(key).parsePlaintextJws(compact)

    }

    // ========================================================================
    // parseClaimsJws with signingKey resolver.
    // ========================================================================

    @Test
    void testParseClaimsWithSigningKeyResolver() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return key
            }
        }

        Jws jws = Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact)

        assertThat jws.getBody().getSubject(), is(subject)
    }

    @Test
    void testParseClaimsWithSigningKeyResolverInvalidKey() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return randomKey()
            }
        }

        thrown.expect SignatureException
        thrown.expectMessage is('JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.')

        Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact)

    }

    @Test
    void testParseClaimsWithSigningKeyResolverAndKey() {

        String subject = 'Joe'

        SecretKeySpec key = new SecretKeySpec(randomKey(), "HmacSHA256")

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return randomKey()
            }
        }

        thrown.expect IllegalStateException
        thrown.expectMessage is('A signing key resolver and a key object cannot both be specified. Choose either.')

        Jwts.parser().setSigningKey(key).setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact)

    }

    @Test
    void testParseClaimsWithSigningKeyResolverAndKeyBytes() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {
                return randomKey()
            }
        }

        thrown.expect IllegalStateException
        thrown.expectMessage is('A signing key resolver and key bytes cannot both be specified. Choose either.')

        Jwts.parser().setSigningKey(key).setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact)

    }

    @Test
    void testParseClaimsWithNullSigningKeyResolver() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        thrown.expect IllegalArgumentException
        thrown.expectMessage is('SigningKeyResolver cannot be null.')

        Jwts.parser().setSigningKeyResolver(null).parseClaimsJws(compact)

    }

    @Test
    void testParseClaimsWithInvalidSigningKeyResolverAdapter() {

        String subject = 'Joe'

        byte[] key = randomKey()

        String compact = Jwts.builder().setSubject(subject).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('The specified SigningKeyResolver implementation does not support ' +
            'Claims JWS signing key resolution.  Consider overriding either the resolveSigningKey(JwsHeader, Claims) method ' +
            'or, for HMAC algorithms, the resolveSigningKeyBytes(JwsHeader, Claims) method.')

        Jwts.parser().setSigningKeyResolver(signingKeyResolver).parseClaimsJws(compact)

    }

    // ========================================================================
    // parsePlaintextJws with signingKey resolver.
    // ========================================================================

    @Test
    void testParsePlaintextJwsWithSigningKeyResolverAdapter() {

        String inputPayload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(inputPayload).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, String payload) {
                return key
            }
        }

        Jws<String> jws = Jwts.parser().setSigningKeyResolver(signingKeyResolver).parsePlaintextJws(compact)

        assertThat jws.getBody(), is(inputPayload)
    }

    @Test
    void testParsePlaintextJwsWithSigningKeyResolverInvalidKey() {

        String inputPayload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(inputPayload).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter() {
            @Override
            byte[] resolveSigningKeyBytes(JwsHeader header, String payload) {
                return randomKey()
            }
        }

        thrown.expect SignatureException
        thrown.expectMessage is('JWT signature does not match locally computed signature. JWT validity cannot be asserted and should not be trusted.')

        Jwts.parser().setSigningKeyResolver(signingKeyResolver).parsePlaintextJws(compact)

    }

    @Test
    void testParsePlaintextJwsWithInvalidSigningKeyResolverAdapter() {

        String payload = 'Hello world!'

        byte[] key = randomKey()

        String compact = Jwts.builder().setPayload(payload).signWith(SignatureAlgorithm.HS256, key).compact()

        def signingKeyResolver = new SigningKeyResolverAdapter()

        thrown.expect UnsupportedJwtException
        thrown.expectMessage is('The specified SigningKeyResolver implementation does not support plaintext ' +
            'JWS signing key resolution.  Consider overriding either the resolveSigningKey(JwsHeader, String) ' +
            'method or, for HMAC algorithms, the resolveSigningKeyBytes(JwsHeader, String) method.')

        Jwts.parser().setSigningKeyResolver(signingKeyResolver).parsePlaintextJws(compact)

    }
}
