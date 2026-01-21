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

import dorkbox.crypto.CryptoDSA.generateKeyPair
import dorkbox.crypto.CryptoDSA.generateSignature
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.DSAParameter
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters
import org.bouncycastle.crypto.params.DSAPublicKeyParameters
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.crypto.util.PublicKeyFactory
import org.junit.Assert
import org.junit.Test
import java.io.IOException
import java.security.SecureRandom

@Suppress("deprecation")
class DsaTest {
    // Note: this is here just for keeping track of how this is done. This should NOT be used, and instead ECC crypto used instead.
    @Test
    fun Dsa() {
        val bytes = "hello, my name is inigo montoya".toByteArray()

        val generateKeyPair = generateKeyPair(SecureRandom(entropySeed.toByteArray()), 1024)
        val privateKey = generateKeyPair.private as DSAPrivateKeyParameters
        val publicKey = generateKeyPair.public as DSAPublicKeyParameters


        val signature = generateSignature(privateKey, SecureRandom(entropySeed.toByteArray()), bytes)

        val verify1 = CryptoDSA.verifySignature(publicKey, bytes, signature)

        if (!verify1) {
            Assert.fail("failed signature verification")
        }


        val bytes2 = "hello, my name is inigo montoya FAILED VERSION".toByteArray()

        if (bytes.contentEquals(bytes2)) {
            Assert.fail("failed to create different byte arrays for testing bad messages")
        }



        val verify2 = CryptoDSA.verifySignature(publicKey, bytes2, signature)

        if (verify2) {
            Assert.fail("failed signature verification with bad message")
        }
    }

    @Test
    @Throws(IOException::class)
    fun DsaJceSerializaion() {
        val generateKeyPair = generateKeyPair(SecureRandom(entropySeed.toByteArray()), 1024)
        val privateKey = generateKeyPair.private as DSAPrivateKeyParameters
        val publicKey = generateKeyPair.public as DSAPublicKeyParameters


        // public key as bytes.
        var parameters = publicKey.parameters
        val bs = SubjectPublicKeyInfo(
            AlgorithmIdentifier(
                X9ObjectIdentifiers.id_dsa, DSAParameter(parameters.p, parameters.q, parameters.g).toASN1Primitive()
            ), ASN1Integer(publicKey.y)
        ).getEncoded()



        parameters = privateKey.parameters
        val bs2 = PrivateKeyInfo(
            AlgorithmIdentifier(
                X9ObjectIdentifiers.id_dsa, DSAParameter(parameters.p, parameters.q, parameters.g).toASN1Primitive()
            ), ASN1Integer(privateKey.x)
        ).getEncoded()



        val privateKey2 = PrivateKeyFactory.createKey(bs2) as DSAPrivateKeyParameters
        val publicKey2 = PublicKeyFactory.createKey(bs) as DSAPublicKeyParameters



        // test via signing
        val bytes = "hello, my name is inigo montoya".toByteArray()


        val signature = generateSignature(privateKey, SecureRandom(entropySeed.toByteArray()), bytes)

        val verify1 = CryptoDSA.verifySignature(publicKey, bytes, signature)

        if (!verify1) {
            Assert.fail("failed signature verification")
        }


        val verify2 = CryptoDSA.verifySignature(publicKey2, bytes, signature)

        if (!verify2) {
            Assert.fail("failed signature verification")
        }



        // now reverse who signs what.
        val signatureB = generateSignature(privateKey2, SecureRandom(entropySeed.toByteArray()), bytes)

        val verifyB1 = CryptoDSA.verifySignature(publicKey, bytes, signatureB)

        if (!verifyB1) {
            Assert.fail("failed signature verification")
        }


        val verifyB2 = CryptoDSA.verifySignature(publicKey2, bytes, signatureB)

        if (!verifyB2) {
            Assert.fail("failed signature verification")
        }
    }

    companion object {
        private const val entropySeed = "asdjhaffasttjjhgpx600gn,-356268909087s0dfgkjh255124515hasdg87"
    }
}
