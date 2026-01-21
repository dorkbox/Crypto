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
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.crypto.params.*
import org.junit.Assert
import org.junit.Test
import java.io.IOException
import java.math.BigInteger
import java.security.SecureRandom
import java.util.*

class x509Test {
    @Test
    @Throws(IOException::class)
    fun EcdsaCertificate() {
        // create the certificate
        val expiry = Calendar.getInstance()
        expiry.add(Calendar.DAY_OF_YEAR, 360)

        val startDate = Date() // time from which certificate is valid
        val expiryDate = expiry.getTime() // time after which certificate is not valid
        val serialNumber = BigInteger.valueOf(System.currentTimeMillis()) // serial number for certificate


        val generateKeyPair = CryptoECC.generateKeyPair(CryptoECC.p521_curve, SecureRandom()) // key name from Crypto class
        val privateKey = generateKeyPair.private as ECPrivateKeyParameters
        val publicKey = generateKeyPair.public as ECPublicKeyParameters



        val ECDSAx509Certificate = CryptoX509.ECDSA.createCertHolder(
            "SHA384", startDate, expiryDate, X500Name("CN=Test"), X500Name("CN=Test"), serialNumber, privateKey, publicKey
        )
        // make sure it's a valid cert.
        if (ECDSAx509Certificate != null) {
            val valid = CryptoX509.ECDSA.validate(ECDSAx509Certificate)

            if (!valid) {
                Assert.fail("Unable to verify a x509 certificate.")
            }
        }
        else {
            Assert.fail("Unable to create a x509 certificate.")
        }

        // now sign something, then verify the signature.
        val data = "My keyboard is awesome".toByteArray()
        val signatureBlock = CryptoX509.createSignature(data, ECDSAx509Certificate!!, privateKey)

        val verifySignature = CryptoX509.ECDSA.verifySignature(signatureBlock!!, publicKey)

        if (!verifySignature) {
            Assert.fail("Unable to verify a x509 certificate signature.")
        }
    }

    @Test
    @Throws(IOException::class)
    fun DsaCertificate() {
        // create the certificate
        val expiry = Calendar.getInstance()
        expiry.add(Calendar.DAY_OF_YEAR, 360)

        val startDate = Date() // time from which certificate is valid
        val expiryDate = expiry.getTime() // time after which certificate is not valid
        val serialNumber = BigInteger.valueOf(System.currentTimeMillis()) // serial number for certificate


        val generateKeyPair = generateKeyPair(SecureRandom(entropySeed.toByteArray()), 1024)


        val privateKey = generateKeyPair.private as DSAPrivateKeyParameters
        val publicKey = generateKeyPair.public as DSAPublicKeyParameters



        val DSAx509Certificate = CryptoX509.DSA.createCertHolder(
            startDate, expiryDate, X500Name("CN=Test"), X500Name("CN=Test"), serialNumber, privateKey, publicKey
        )
        // make sure it's a valid cert.
        if (DSAx509Certificate != null) {
            val valid = CryptoX509.DSA.validate(DSAx509Certificate)

            if (!valid) {
                Assert.fail("Unable to verify a x509 certificate.")
            }
        }
        else {
            Assert.fail("Unable to create a x509 certificate.")
        }

        // now sign something, then verify the signature.
        val data = "My keyboard is awesome".toByteArray()
        val signatureBlock = CryptoX509.createSignature(data, DSAx509Certificate!!, privateKey)

        val verifySignature = CryptoX509.DSA.verifySignature(signatureBlock!!, publicKey)

        if (!verifySignature) {
            Assert.fail("Unable to verify a x509 certificate signature.")
        }
    }

    @Test
    @Throws(IOException::class)
    fun RsaCertificate() {
        // create the certificate
        val expiry = Calendar.getInstance()
        expiry.add(Calendar.DAY_OF_YEAR, 360)

        val startDate = Date() // time from which certificate is valid
        val expiryDate = expiry.getTime() // time after which certificate is not valid
        val serialNumber = BigInteger.valueOf(System.currentTimeMillis()) // serial number for certificate

        val generateKeyPair = CryptoRSA.generateKeyPair(SecureRandom(entropySeed.toByteArray()), 1024)
        val privateKey = generateKeyPair.private as RSAPrivateCrtKeyParameters
        val publicKey = generateKeyPair.public as RSAKeyParameters


        val RSAx509Certificate = CryptoX509.RSA.createCertHolder(
            startDate, expiryDate, X500Name("CN=Test"), X500Name("CN=Test"), serialNumber, privateKey, publicKey
        )
        // make sure it's a valid cert.
        if (RSAx509Certificate != null) {
            val valid = CryptoX509.RSA.validate(RSAx509Certificate)

            if (!valid) {
                Assert.fail("Unable to verify a x509 certificate.")
            }
        }
        else {
            Assert.fail("Unable to create a x509 certificate.")
        }

        // now sign something, then verify the signature.
        val data = "My keyboard is awesome".toByteArray()
        val signatureBlock = CryptoX509.createSignature(data, RSAx509Certificate!!, privateKey)

        val verifySignature = CryptoX509.RSA.verifySignature(signatureBlock!!, publicKey)

        if (!verifySignature) {
            Assert.fail("Unable to verify a x509 certificate signature.")
        }
    }

    companion object {
        private const val entropySeed = "asdjhaffasdgfaasttjjhgpx600gn,-356268909087s0dfg4-42kjh255124515hasdg87"
    }
}
