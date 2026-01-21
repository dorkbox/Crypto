/*
 * Copyright 2026 dorkbox, llc
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
package dorkbox.crypto

import com.esotericsoftware.kryo.Kryo
import com.esotericsoftware.kryo.io.Input
import com.esotericsoftware.kryo.io.Output
import dorkbox.serializers.bouncycastle.RsaPrivateKeySerializer
import dorkbox.serializers.bouncycastle.RsaPublicKeySerializer
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.encodings.OAEPEncoding
import org.bouncycastle.crypto.engines.RSAEngine
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.signers.PSSSigner
import org.junit.Assert
import org.junit.Test
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.SecureRandom


class RsaTest {
    var logger: Logger? = LoggerFactory.getLogger(this.javaClass)

    @Suppress("deprecation")
    @Test
    fun Rsa() {
        val bytes = "hello, my name is inigo montoya".toByteArray()

        val key = CryptoRSA.generateKeyPair(SecureRandom(entropySeed.toByteArray()), 1024)

        val public1 = key.public as RSAKeyParameters
        val private1 = key.private as RSAPrivateCrtKeyParameters


        val engine = RSAEngine()
        val digest = SHA1Digest()
        val rsaEngine = OAEPEncoding(engine, digest)

        // test encrypt/decrypt
        val encryptRSA = CryptoRSA.encrypt(rsaEngine, public1, bytes, logger)
        val decryptRSA = CryptoRSA.decrypt(rsaEngine, private1, encryptRSA, logger)

        if (bytes.contentEquals(encryptRSA)) {
            Assert.fail("bytes should not be equal")
        }

        if (!bytes.contentEquals(decryptRSA)) {
            Assert.fail("bytes not equal")
        }

        // test signing/verification
        val signer = PSSSigner(engine, digest, digest.digestSize)

        val signatureRSA = CryptoRSA.sign(signer, private1, bytes, logger)
        val verify = CryptoRSA.verify(signer, public1, signatureRSA, bytes)

        if (!verify) {
            Assert.fail("failed signature verification")
        }
    }


    @Suppress("deprecation")
    @Test
    @Throws(IOException::class)
    fun RsaSerialization() {
        val keyGen = RSAKeyPairGenerator()
        val params = RSAKeyGenerationParameters(
            BigInteger("65537"),  // public exponent
            SecureRandom(entropySeed.toByteArray()),  //pnrg
            1024,  // key length
            8
        ) //the number of iterations of the Miller-Rabin primality test.
        keyGen.init(params)


        val key = keyGen.generateKeyPair()

        val public1 = key.public as RSAKeyParameters
        val private1 = key.private as RSAPrivateCrtKeyParameters


        val kryo = Kryo()
        kryo.register(RSAKeyParameters::class.java, RsaPublicKeySerializer())
        kryo.register(RSAPrivateCrtKeyParameters::class.java, RsaPrivateKeySerializer())

        // Test output to stream, large buffer.
        var outStream = ByteArrayOutputStream()
        var output = Output(outStream, 4096)
        kryo.writeClassAndObject(output, public1)
        output.flush()

        // Test input from stream, large buffer.
        var input = Input(ByteArrayInputStream(outStream.toByteArray()), 4096)
        val public2 = kryo.readClassAndObject(input) as RSAKeyParameters


        if (!CryptoRSA.compare(public1, public2)) {
            Assert.fail("public keys not equal")
        }


        // Test output to stream, large buffer.
        outStream = ByteArrayOutputStream()
        output = Output(outStream, 4096)
        kryo.writeClassAndObject(output, private1)
        output.flush()

        // Test input from stream, large buffer.
        input = Input(ByteArrayInputStream(outStream.toByteArray()), 4096)
        val private2 = kryo.readClassAndObject(input) as RSAPrivateCrtKeyParameters


        if (!CryptoRSA.compare(private1, private2)) {
            Assert.fail("private keys not equal")
        }
    }

    companion object {
        private const val entropySeed = "asdjhaffasttjjhgpx600gn,-356268909087s0dfgkjh255124515hasdg87"
    }
}
