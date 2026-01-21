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
import dorkbox.serializers.bouncycastle.EccPrivateKeySerializer
import dorkbox.serializers.bouncycastle.EccPublicKeySerializer
import dorkbox.serializers.bouncycastle.IesParametersSerializer
import dorkbox.serializers.bouncycastle.IesWithCipherParametersSerializer
import org.bouncycastle.crypto.BasicAgreement
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.util.encoders.Hex
import org.junit.Assert
import org.junit.Test
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.SecureRandom

class EccTest {
    var logger: Logger? = LoggerFactory.getLogger(this.javaClass)

    @Test
    @Throws(IOException::class)
    fun EccStreamMode() {
        val secureRandom = SecureRandom()

        val key1 = CryptoECC.generateKeyPair(CryptoECC.default_curve, secureRandom)
        val key2 = CryptoECC.generateKeyPair(CryptoECC.default_curve, secureRandom)

        val cipherParams = CryptoECC.generateSharedParameters(secureRandom)

        val encrypt = CryptoECC.createEngine()
        val decrypt = CryptoECC.createEngine()


        // note: we want an ecc key that is AT LEAST 512 bits! (which is equal to AES 256)
        // using 521 bits from curve.
        val private1: CipherParameters? = key1.private
        val public1: CipherParameters? = key1.public

        val private2: CipherParameters? = key2.private
        val public2: CipherParameters? = key2.public

        val message = Hex.decode(
            "123456784358754934597967249867359283792374987692348750276509765091834790abcdef123456784358754934597967249867359283792374987692348750276509765091834790abcdef123456784358754934597967249867359283792374987692348750276509765091834790abcdef"
        )


        // test stream mode
        val encrypted = CryptoECC.encrypt(encrypt, private1, public2, cipherParams, message, logger)
        Assert.assertTrue(encrypted != null)

        val plaintext = CryptoECC.decrypt(decrypt, private2, public1, cipherParams, encrypted!!, logger)

        if (encrypted.contentEquals(message)) {
            Assert.fail("stream cipher test failed")
        }

        if (!plaintext.contentEquals(message)) {
            Assert.fail("stream cipher test failed")
        }
    }

    @Test
    @Throws(IOException::class)
    fun EccAesMode() {
        // test AES encrypt mode
        val secureRandom = SecureRandom()

        val key1 = CryptoECC.generateKeyPair(CryptoECC.default_curve, secureRandom)
        val key2 = CryptoECC.generateKeyPair(CryptoECC.default_curve, secureRandom)


        val aesEngine1 = PaddedBufferedBlockCipher(CBCBlockCipher(AESEngine()))
        val aesEngine2 = PaddedBufferedBlockCipher(CBCBlockCipher(AESEngine()))

        val cipherParams = CryptoECC.generateSharedParametersWithCipher(secureRandom)


        val encrypt = CryptoECC.createEngine(aesEngine1)
        val decrypt = CryptoECC.createEngine(aesEngine2)


        // note: we want an ecc key that is AT LEAST 512 bits! (which is equal to AES 256)
        // using 521 bits from curve.
        val private1: CipherParameters? = key1.private
        val public1: CipherParameters? = key1.public

        val private2: CipherParameters? = key2.private
        val public2: CipherParameters? = key2.public

        val message =
            Hex.decode("123456784358754934597967249867359283792374987692348750276509765091834790abcdef123456784358754934597967249867359283792374987692348750276509765091834790abcdef123456784358754934597967249867359283792374987692348750276509765091834790abcdef")

        // test stream mode
        val encrypted = CryptoECC.encrypt(encrypt, private1, public2, cipherParams, message, logger)
        Assert.assertTrue(encrypted != null)
        val plaintext = CryptoECC.decrypt(decrypt, private2, public1, cipherParams, encrypted!!, logger)

        if (encrypted.contentEquals(message)) {
            Assert.fail("stream cipher test failed")
        }

        if (!plaintext.contentEquals(message)) {
            Assert.fail("stream cipher test failed")
        }
    }

    @Test
    @Throws(IOException::class)
    fun Ecdh() {
        // test DH key exchange
        val secureRandom = SecureRandom()

        val key1 = CryptoECC.generateKeyPair(CryptoECC.default_curve, secureRandom)
        val key2 = CryptoECC.generateKeyPair(CryptoECC.default_curve, secureRandom)

        val e1: BasicAgreement = ECDHCBasicAgreement()
        val e2: BasicAgreement = ECDHCBasicAgreement()

        e1.init(key1.private)
        e2.init(key2.private)

        val k1 = e1.calculateAgreement(key2.public)
        val k2 = e2.calculateAgreement(key1.public)

        if (k1 != k2) {
            Assert.fail("ECDHC cipher test failed")
        }
    }

    @Test
    @Throws(IOException::class)
    fun EccDsa() {
        val secureRandom = SecureRandom()

        val key1 = CryptoECC.generateKeyPair(CryptoECC.default_curve, secureRandom)

        val param = ParametersWithRandom(key1.private, SecureRandom())

        val ecdsa = ECDSASigner()

        ecdsa.init(true, param)

        val message = BigInteger("345234598734987394672039478602934578").toByteArray()
        val sig = ecdsa.generateSignature(message)


        ecdsa.init(false, key1.public)

        if (!ecdsa.verifySignature(message, sig[0], sig[1])) {
            Assert.fail("ECDSA signature fails")
        }
    }

    @Test
    fun EccSerialization() {
        val secureRandom = SecureRandom()

        val key1 = CryptoECC.generateKeyPair(CryptoECC.default_curve, secureRandom)

        val cipherAParams = CryptoECC.generateSharedParameters(secureRandom)
        val cipherBParams = CryptoECC.generateSharedParametersWithCipher(secureRandom)


        // note: we want an ecc key that is AT LEAST 512 bits! (which is equal to AES 256)
        // using 521 bits from curve.
        val private1 = key1.private as ECPrivateKeyParameters
        val public1 = key1.public as ECPublicKeyParameters?


        val kryo = Kryo()
        kryo.register(IESParameters::class.java, IesParametersSerializer())
        kryo.register(IESWithCipherParameters::class.java, IesWithCipherParametersSerializer())
        kryo.register(ECPublicKeyParameters::class.java, EccPublicKeySerializer())
        kryo.register(ECPrivateKeyParameters::class.java, EccPrivateKeySerializer())



        // Test output to stream, large buffer.
        var outStream = ByteArrayOutputStream()
        var output = Output(outStream, 4096)
        kryo.writeClassAndObject(output, cipherAParams)
        output.flush()

        // Test input from stream, large buffer.
        var input = Input(ByteArrayInputStream(outStream.toByteArray()), 4096)
        val cipherAParams2 = kryo.readClassAndObject(input) as IESParameters


        if (!CryptoECC.compare(cipherAParams, cipherAParams2)) {
            Assert.fail("cipher parameters not equal")
        }

        // Test output to stream, large buffer.
        outStream = ByteArrayOutputStream()
        output = Output(outStream, 4096)
        kryo.writeClassAndObject(output, cipherBParams)
        output.flush()

        // Test input from stream, large buffer.
        input = Input(ByteArrayInputStream(outStream.toByteArray()), 4096)
        val cipherBParams2 = kryo.readClassAndObject(input) as IESWithCipherParameters

        if (!CryptoECC.compare(cipherBParams, cipherBParams2)) {
            Assert.fail("cipher parameters not equal")
        }


        // Test output to stream, large buffer.
        outStream = ByteArrayOutputStream()
        output = Output(outStream, 4096)
        kryo.writeClassAndObject(output, private1)
        output.flush()

        // Test input from stream, large buffer.
        input = Input(ByteArrayInputStream(outStream.toByteArray()), 4096)
        val private2 = kryo.readClassAndObject(input) as ECPrivateKeyParameters

        if (!CryptoECC.compare(private1, private2)) {
            Assert.fail("private keys not equal")
        }


        // Test output to stream, large buffer.
        outStream = ByteArrayOutputStream()
        output = Output(outStream, 4096)
        kryo.writeClassAndObject(output, public1)
        output.flush()

        // Test input from stream, large buffer.
        input = Input(ByteArrayInputStream(outStream.toByteArray()), 4096)
        val public2 = kryo.readClassAndObject(input) as ECPublicKeyParameters?

        if (!CryptoECC.compare(public1, public2)) {
            Assert.fail("public keys not equal")
        }
    }


    @Test
    @Throws(IOException::class)
    fun EccJceSerialization() {
        val generateKeyPair = CryptoECC.generateKeyPair(CryptoECC.default_curve, SecureRandom())
        val privateKey = generateKeyPair.private as ECPrivateKeyParameters
        val publicKey = generateKeyPair.public as ECPublicKeyParameters


        val bcecPublicKey = BCECPublicKey("EC", publicKey, null as ECParameterSpec?, BouncyCastleProvider.CONFIGURATION)
        val publicBytes = bcecPublicKey.getEncoded()



        // relies on the BC public key.
        val bcecPrivateKey = BCECPrivateKey("EC", privateKey, bcecPublicKey, null as ECParameterSpec?, BouncyCastleProvider.CONFIGURATION)
        val privateBytes = bcecPrivateKey.getEncoded()



        val publicKey2 = PublicKeyFactory.createKey(publicBytes) as ECPublicKeyParameters
        val privateKey2 = PrivateKeyFactory.createKey(privateBytes) as ECPrivateKeyParameters



        // test via signing
        val bytes = "hello, my name is inigo montoya".toByteArray()


        val signature = CryptoECC.generateSignature("SHA384", privateKey, SecureRandom(entropySeed.toByteArray()), bytes)

        val verify1 = CryptoECC.verifySignature("SHA384", publicKey, bytes, signature)

        if (!verify1) {
            Assert.fail("failed signature verification")
        }

        val verify2 = CryptoECC.verifySignature("SHA384", publicKey2, bytes, signature)

        if (!verify2) {
            Assert.fail("failed signature verification")
        }



        // now reverse who signs what.
        val signatureB = CryptoECC.generateSignature("SHA384", privateKey2, SecureRandom(entropySeed.toByteArray()), bytes)

        val verifyB1 = CryptoECC.verifySignature("SHA384", publicKey, bytes, signatureB)

        if (!verifyB1) {
            Assert.fail("failed signature verification")
        }

        val verifyB2 = CryptoECC.verifySignature("SHA384", publicKey2, bytes, signatureB)

        if (!verifyB2) {
            Assert.fail("failed signature verification")
        }
    }

    companion object {
        private const val entropySeed = "asdjhaffasttjasdasdgfgaerym0698768.,./8909087s0dfgkjgb49bmngrSGDSG#"
    }
}
