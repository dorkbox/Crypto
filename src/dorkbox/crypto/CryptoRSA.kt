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

import org.bouncycastle.crypto.AsymmetricBlockCipher
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.crypto.params.RSAKeyParameters
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters
import org.bouncycastle.crypto.signers.PSSSigner
import org.slf4j.Logger
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.SecureRandom
import kotlin.math.min

/**
 * This is here just for keeping track of how this is done. This should NOT be used, and instead use ECC crypto.
 */
@Deprecated("")
object CryptoRSA {
    /**
     * Gets the version number.
     */
    const val version = Crypto.version

    fun generateKeyPair(secureRandom: SecureRandom, keyLength: Int): AsymmetricCipherKeyPair {
        val keyGen = RSAKeyPairGenerator()
        val params = RSAKeyGenerationParameters(
            BigInteger("65537"),  // public exponent
            secureRandom,  //pnrg
            keyLength,  // key length
            8
        ) //the number of iterations of the Miller-Rabin primality test.
        keyGen.init(params)
        return keyGen.generateKeyPair()
    }

    /**
     * RSA encrypt using public key A, and sign data with private key B.
     * 
     * 
     * byte[0][] = encrypted data byte[1][] = signature
     * 
     * @param logger
     * may be null, if no log output is necessary
     * 
     * @return empty byte[][] if error
     */
    fun encryptAndSign(
        rsaEngine: AsymmetricBlockCipher,
        digest: Digest,
        rsaPublicKeyA: RSAKeyParameters?,
        rsaPrivateKeyB: RSAPrivateCrtKeyParameters?,
        bytes: ByteArray,
        logger: Logger?
    ): Array<ByteArray?> {
        if (bytes.size == 0) {
            return Array<ByteArray?>(0) { ByteArray(0) }
        }

        val encryptBytes = encrypt(rsaEngine, rsaPublicKeyA, bytes, logger)

        if (encryptBytes.size == 0) {
            return Array<ByteArray?>(0) { ByteArray(0) }
        }

        // now sign it.
        val signer = PSSSigner(rsaEngine, digest, digest.getDigestSize())

        val signatureRSA = sign(signer, rsaPrivateKeyB, encryptBytes, logger)

        if (signatureRSA.size == 0) {
            return Array<ByteArray?>(0) { ByteArray(0) }
        }

        val total = arrayOfNulls<ByteArray>(2)
        total[0] = encryptBytes
        total[1] = signatureRSA


        return total
    }

    /**
     * RSA verify data with public key B, and decrypt using private key A.
     * 
     * @param logger
     * may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    fun decryptAndVerify(
        rsaEngine: AsymmetricBlockCipher,
        digest: Digest,
        rsaPublicKeyA: RSAKeyParameters?,
        rsaPrivateKeyB: RSAPrivateCrtKeyParameters?,
        encryptedData: ByteArray,
        signature: ByteArray,
        logger: Logger?
    ): ByteArray? {
        if (encryptedData.size == 0 || signature.size == 0) {
            return ByteArray(0)
        }

        // verify encrypted data.
        val signer = PSSSigner(rsaEngine, digest, digest.getDigestSize())

        val verify = verify(signer, rsaPublicKeyA, signature, encryptedData)
        if (!verify) {
            return ByteArray(0)
        }

        return decrypt(rsaEngine, rsaPrivateKeyB, encryptedData, logger)
    }

    /**
     * RSA encrypts data with a specified key.
     * 
     * @param logger
     * may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    fun encrypt(rsaEngine: AsymmetricBlockCipher, rsaPublicKey: RSAKeyParameters?, bytes: ByteArray, logger: Logger?): ByteArray {
        rsaEngine.init(true, rsaPublicKey)

        try {
            val inputBlockSize = rsaEngine.getInputBlockSize()
            if (inputBlockSize < bytes.size) {
                val outSize = rsaEngine.getOutputBlockSize()
                val realsize = Math.round(bytes.size / (outSize * 1.0) + 0.5).toInt()
                val buffer = ByteBuffer.allocateDirect(outSize * realsize)

                var position = 0

                while (position < bytes.size) {
                    val size = min(inputBlockSize, bytes.size - position)

                    val block = rsaEngine.processBlock(bytes, position, size)
                    buffer.put(block, 0, block.size)

                    position += size
                }


                return buffer.array()
            }
            else {
                return rsaEngine.processBlock(bytes, 0, bytes.size)
            }
        }
        catch (e: Exception) {
            if (logger != null) {
                logger.error("Unable to perform RSA cipher.", e)
            }
            return ByteArray(0)
        }
    }

    /**
     * RSA decrypt data with a specified key.
     * 
     * @param logger
     * may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    fun decrypt(
        rsaEngine: AsymmetricBlockCipher,
        rsaPrivateKey: RSAPrivateCrtKeyParameters?,
        bytes: ByteArray,
        logger: Logger?
    ): ByteArray? {
        rsaEngine.init(false, rsaPrivateKey)

        try {
            val inputBlockSize = rsaEngine.getInputBlockSize()
            if (inputBlockSize < bytes.size) {
                val outSize = rsaEngine.getOutputBlockSize()
                val realsize = Math.round(bytes.size / (outSize * 1.0) + 0.5).toInt()
                val buffer = ByteArrayOutputStream(outSize * realsize)

                var position = 0

                while (position < bytes.size) {
                    val size = min(inputBlockSize, bytes.size - position)

                    val block = rsaEngine.processBlock(bytes, position, size)
                    buffer.write(block, 0, block.size)

                    position += size
                }


                return buffer.toByteArray()
            }
            else {
                return rsaEngine.processBlock(bytes, 0, bytes.size)
            }
        }
        catch (e: Exception) {
            if (logger != null) {
                logger.error("Unable to perform RSA cipher.", e)
            }
            return ByteArray(0)
        }
    }

    /**
     * RSA sign data with a specified key.
     * 
     * @param logger
     * may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    fun sign(signer: PSSSigner, rsaPrivateKey: RSAPrivateCrtKeyParameters?, mesg: ByteArray, logger: Logger?): ByteArray {
        signer.init(true, rsaPrivateKey)
        signer.update(mesg, 0, mesg.size)

        try {
            return signer.generateSignature()
        }
        catch (e: Exception) {
            if (logger != null) {
                logger.error("Unable to perform RSA cipher.", e)
            }
            return ByteArray(0)
        }
    }

    /**
     * RSA verify data with a specified key.
     */
    fun verify(signer: PSSSigner, rsaPublicKey: RSAKeyParameters?, sig: ByteArray?, mesg: ByteArray): Boolean {
        signer.init(false, rsaPublicKey)
        signer.update(mesg, 0, mesg.size)

        return signer.verifySignature(sig)
    }

    fun compare(publicA: RSAKeyParameters, publicB: RSAKeyParameters): Boolean {
        if (publicA.getExponent() != publicB.getExponent()) {
            return false
        }
        if (publicA.getModulus() != publicB.getModulus()) {
            return false
        }

        return true
    }

    fun compare(private1: RSAPrivateCrtKeyParameters, private2: RSAPrivateCrtKeyParameters): Boolean {
        if (private1.getModulus() != private2.getModulus()) {
            return false
        }
        if (private1.getExponent() != private2.getExponent()) {
            return false
        }
        if (private1.getDP() != private2.getDP()) {
            return false
        }
        if (private1.getDQ() != private2.getDQ()) {
            return false
        }
        if (private1.getP() != private2.getP()) {
            return false
        }
        if (private1.getPublicExponent() != private2.getPublicExponent()) {
            return false
        }
        if (private1.getQ() != private2.getQ()) {
            return false
        }
        if (private1.getQInv() != private2.getQInv()) {
            return false
        }

        return true
    }
}
