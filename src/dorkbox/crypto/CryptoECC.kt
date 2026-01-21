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

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement
import org.bouncycastle.crypto.digests.SHA384Digest
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.engines.IESEngine
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.generators.KDF2BytesGenerator
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.*
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.jcajce.provider.util.DigestFactory
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECParameterSpec
import org.slf4j.Logger
import java.math.BigInteger
import java.security.SecureRandom

/**
 * ECC crypto functions
 */
object CryptoECC {
    /**
     * Gets the version number.
     */
    const val version = Crypto.version

    const val p521_curve: String = "secp521r1"
    const val curve25519: String = "curve25519"
    val default_curve: String = curve25519

    const val macSize: Int = 512

    // on NIST vs 25519 vs Brainpool, see:
    //  - http://ogryb.blogspot.de/2014/11/why-i-dont-trust-nist-p-256.html
    //  - http://credelius.com/credelius/?p=97
    //  - http://safecurves.cr.yp.to/
    // we should be using 25519, because NIST and brainpool are "unsafe". Brainpool is "more random" than 25519, but is still not considered safe.
    // more info about ECC from:
    // http://www.johannes-bauer.com/compsci/ecc/?menuid=4
    // http://stackoverflow.com/questions/7419183/problems-implementing-ecdh-on-android-using-bouncycastle
    // http://tools.ietf.org/html/draft-jivsov-openpgp-ecc-06#page-4
    // http://www.nsa.gov/ia/programs/suiteb_cryptography/
    // https://github.com/nelenkov/ecdh-kx/blob/master/src/org/nick/ecdhkx/Crypto.java
    // http://nelenkov.blogspot.com/2011/12/using-ecdh-on-android.html
    // http://www.secg.org/collateral/sec1_final.pdf
    /**
     * Uses SHA512
     */
    fun createEngine(): IESEngine {
        return IESEngine(ECDHCBasicAgreement(), KDF2BytesGenerator(SHA384Digest()), HMac(SHA512Digest()))
    }

    /**
     * Uses SHA512
     */
    fun createEngine(aesEngine: PaddedBufferedBlockCipher?): IESEngine {
        return IESEngine(
            ECDHCBasicAgreement(), KDF2BytesGenerator(SHA384Digest()), HMac(SHA512Digest()), aesEngine
        )
    }

    /**
     * These parameters are shared between the two parties. These are a NONCE (use ONCE number!!)
     */
    fun generateSharedParameters(secureRandom: SecureRandom): IESParameters {
        val macSize = macSize // must be the MAC size

        // MUST be random EACH TIME encrypt/sign happens!
        val derivation = ByteArray(macSize / 8)
        val encoding = ByteArray(macSize / 8)

        secureRandom.nextBytes(derivation)
        secureRandom.nextBytes(encoding)

        return IESParameters(derivation, encoding, macSize)
    }

    /**
     * AES-256 ONLY!
     */
    fun generateSharedParametersWithCipher(secureRandom: SecureRandom): IESWithCipherParameters {
        val macSize = macSize // must be the MAC size

        val derivation = ByteArray(macSize / 8) // MUST be random EACH TIME encrypt/sign happens!
        val encoding = ByteArray(macSize / 8)

        secureRandom.nextBytes(derivation)
        secureRandom.nextBytes(encoding)

        return IESWithCipherParameters(derivation, encoding, macSize, 256)
    }

    fun generateKeyPair(eccCurveName: String, secureRandom: SecureRandom): AsymmetricCipherKeyPair {
        val eccSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec(eccCurveName)

        return generateKeyPair(eccSpec, secureRandom)
    }

    fun generateKeyPair(eccSpec: ECParameterSpec, secureRandom: SecureRandom): AsymmetricCipherKeyPair {
        val ecParams = ECKeyGenerationParameters(ECDomainParameters(eccSpec.curve, eccSpec.g, eccSpec.n), secureRandom)

        val ecKeyGen = ECKeyPairGenerator()
        ecKeyGen.init(ecParams)

        return ecKeyGen.generateKeyPair()
    }

    /**
     * ECC encrypts data with a specified key.
     * 
     * @param logger
     * may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    fun encrypt(
        eccEngine: IESEngine,
        private1: CipherParameters?,
        public2: CipherParameters?,
        cipherParams: IESParameters?,
        message: ByteArray,
        logger: Logger?
    ): ByteArray? {
        eccEngine.init(true, private1, public2, cipherParams)

        try {
            return eccEngine.processBlock(message, 0, message.size)
        }
        catch (e: Exception) {
            if (logger != null) {
                logger.error("Unable to perform ECC cipher.", e)
            }
            return null
        }
    }

    /**
     * ECC decrypt data with a specified key.
     * 
     * @param logger
     * may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    fun decrypt(
        eccEngine: IESEngine,
        private2: CipherParameters?,
        public1: CipherParameters?,
        cipherParams: IESParameters?,
        encrypted: ByteArray,
        logger: Logger?
    ): ByteArray? {
        eccEngine.init(false, private2, public1, cipherParams)

        try {
            return eccEngine.processBlock(encrypted, 0, encrypted.size)
        }
        catch (e: Exception) {
            if (logger != null) {
                logger.error("Unable to perform ECC cipher.", e)
            }
            return ByteArray(0)
        }
    }

    fun compare(privateA: ECPrivateKeyParameters, privateB: ECPrivateKeyParameters): Boolean {
        val parametersA = privateA.parameters
        val parametersB = privateB.parameters

        // is it the same curve?
        var equals = parametersA.curve.equals(parametersB.curve)
        if (!equals) {
            return false
        }

        equals = parametersA.g.equals(parametersB.g)
        if (!equals) {
            return false
        }


        equals = (parametersA.h == parametersB.h)
        if (!equals) {
            return false
        }

        equals = (parametersA.n == parametersB.n)
        if (!equals) {
            return false
        }

        equals = (privateA.d == privateB.d)

        return equals
    }

    /**
     * @return true if publicA and publicB are NOT NULL, and are both equal to eachother
     */
    @Suppress("SpellCheckingInspection")
    fun compare(publicA: ECPublicKeyParameters?, publicB: ECPublicKeyParameters?): Boolean {
        if (publicA == null || publicB == null) {
            return false
        }


        val parametersA = publicA.parameters
        val parametersB = publicB.parameters

        // is it the same curve?
        var equals = parametersA.curve.equals(parametersB.curve)
        if (!equals) {
            return false
        }

        equals = parametersA.g.equals(parametersB.g)
        if (!equals) {
            return false
        }


        equals = (parametersA.h == parametersB.h)
        if (!equals) {
            return false
        }

        equals = (parametersA.n == parametersB.n)
        if (!equals) {
            return false
        }


        val normalizeA = publicA.q.normalize()
        val normalizeB = publicB.q.normalize()


        val xCoordA = normalizeA.xCoord
        val xCoordB = normalizeB.xCoord

        equals = xCoordA == xCoordB
        if (!equals) {
            return false
        }

        val yCoordA = normalizeA.yCoord
        val yCoordB = normalizeB.yCoord

        equals = yCoordA == yCoordB
        if (!equals) {
            return false
        }

        return true
    }

    fun compare(cipherAParams: IESParameters, cipherBParams: IESParameters): Boolean {
        if (!cipherAParams.derivationV.contentEquals(cipherBParams.derivationV)) {
            return false
        }
        if (!cipherAParams.encodingV.contentEquals(cipherBParams.encodingV)) {
            return false
        }

        if (cipherAParams.macKeySize != cipherBParams.macKeySize) {
            return false
        }
        return true
    }

    fun compare(cipherAParams: IESWithCipherParameters, cipherBParams: IESWithCipherParameters): Boolean {
        if (cipherAParams.cipherKeySize != cipherBParams.cipherKeySize) {
            return false
        }

        // only need to cast one side.
        return compare(cipherAParams as IESParameters, cipherBParams)
    }

    /**
     * The message will have the (digestName) hash calculated and used for the signature.
     * 
     * 
     * The returned signature is the {r,s} signature array.
     */
    fun generateSignature(
        digestName: String,
        privateKey: ECPrivateKeyParameters,
        secureRandom: SecureRandom,
        bytes: ByteArray
    ): Array<BigInteger> {
        val digest = DigestFactory.getDigest(digestName)

        val checksum = ByteArray(digest.digestSize)

        digest.update(bytes, 0, bytes.size)
        digest.doFinal(checksum, 0)

        return generateSignatureForHash(privateKey, secureRandom, checksum)
    }

    /**
     * The message will use the bytes AS THE HASHED VALUE to calculate the signature.
     * 
     * 
     * The returned signature is the {r,s} signature array.
     */
    fun generateSignatureForHash(
        privateKey: ECPrivateKeyParameters,
        secureRandom: SecureRandom,
        hashBytes: ByteArray
    ): Array<BigInteger> {
        val param = ParametersWithRandom(privateKey, secureRandom)

        val ecdsa = ECDSASigner()
        ecdsa.init(true, param)

        return ecdsa.generateSignature(hashBytes)
    }

    /**
     * The message will have the (digestName) hash calculated and used for the signature.
     * 
     * @param signature
     * is the {r,s} signature array.
     * 
     * @return true if the signature is valid
     */
    fun verifySignature(digestName: String, publicKey: ECPublicKeyParameters, message: ByteArray, signature: Array<BigInteger>): Boolean {
        val digest = DigestFactory.getDigest(digestName)

        val checksum = ByteArray(digest.digestSize)

        digest.update(message, 0, message.size)
        digest.doFinal(checksum, 0)

        return verifySignatureHash(publicKey, checksum, signature)
    }

    /**
     * The provided hash will be used in the signature verification.
     * 
     * @param signature
     * is the {r,s} signature array.
     * 
     * @return true if the signature is valid
     */
    fun verifySignatureHash(publicKey: ECPublicKeyParameters, hash: ByteArray?, signature: Array<BigInteger>): Boolean {
        val ecdsa = ECDSASigner()
        ecdsa.init(false, publicKey)

        return ecdsa.verifySignature(hash, signature[0], signature[1])
    }
}
