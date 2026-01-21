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
import org.bouncycastle.crypto.digests.SHA1Digest
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator
import org.bouncycastle.crypto.generators.DSAParametersGenerator
import org.bouncycastle.crypto.params.DSAKeyGenerationParameters
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters
import org.bouncycastle.crypto.params.DSAPublicKeyParameters
import org.bouncycastle.crypto.params.ParametersWithRandom
import org.bouncycastle.crypto.signers.DSASigner
import java.math.BigInteger
import java.security.SecureRandom

/**
 * this is here just for keeping track of how this is done. This should correct and working, but should NOT be used, and instead use ECC
 * crypto.
 */
object CryptoDSA {
    /**
     * Gets the version number.
     */
    const val version = Crypto.version

    /**
     * Generates the DSA key (using RSA and SHA1)
     * 
     * 
     * Note: this is here just for keeping track of how this is done. This should NOT be used, and instead use ECC crypto.
     */
    @Deprecated("Never use DSA, it is VERY insecure!")
    fun generateKeyPair(secureRandom: SecureRandom, keyLength: Int): AsymmetricCipherKeyPair {
        val keyGen = DSAKeyPairGenerator()

        val dsaParametersGenerator = DSAParametersGenerator()
        dsaParametersGenerator.init(keyLength, 20, secureRandom)
        val generateParameters = dsaParametersGenerator.generateParameters()

        val params = DSAKeyGenerationParameters(secureRandom, generateParameters)
        keyGen.init(params)
        return keyGen.generateKeyPair()
    }

    /**
     * The message will have the SHA1 hash calculated and used for the signature.
     * 
     * 
     * Note: this is here just for keeping track of how this is done. This should NOT be used, and instead use ECC crypto.
     * 
     * 
     * The returned signature is the {r,s} signature array.
     */
    @Deprecated("Never use DSA, it is VERY insecure!")
    fun generateSignature(privateKey: DSAPrivateKeyParameters, secureRandom: SecureRandom, message: ByteArray): Array<BigInteger> {
        val param = ParametersWithRandom(privateKey, secureRandom)

        val dsa = DSASigner()

        dsa.init(true, param)


        val sha1Digest = SHA1Digest()
        val checksum = ByteArray(sha1Digest.digestSize)

        sha1Digest.update(message, 0, message.size)
        sha1Digest.doFinal(checksum, 0)

        return dsa.generateSignature(checksum)
    }

    /**
     * The message will have the SHA1 hash calculated and used for the signature.
     * 
     * 
     * Note: this is here just for keeping track of how this is done. This should NOT be used, and instead use ECC crypto.
     * 
     * @param signature
     * is the {r,s} signature array.
     * 
     * @return true if the signature is valid
     */
    @Deprecated("Never use DSA, it is VERY insecure!")
    fun verifySignature(publicKey: DSAPublicKeyParameters, message: ByteArray, signature: Array<BigInteger>): Boolean {
        val sha1Digest = SHA1Digest()
        val checksum = ByteArray(sha1Digest.digestSize)

        sha1Digest.update(message, 0, message.size)
        sha1Digest.doFinal(checksum, 0)


        val dsa = DSASigner()

        dsa.init(false, publicKey)

        return dsa.verifySignature(checksum, signature[0], signature[1])
    }
}
