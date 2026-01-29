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

import dorkbox.updates.Updates.add
import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.PBEParametersGenerator
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.NoSuchAlgorithmException
import java.security.Security
import java.util.*
import java.util.jar.*
import javax.crypto.Cipher

/**
 * http://en.wikipedia.org/wiki/NSA_Suite_B http://www.nsa.gov/ia/programs/suiteb_cryptography/
 *
 *
 * NSA Suite B
 *
 *
 * TOP-SECRET LEVEL AES256/GCM ECC with 384-bit prime curve (FIPS PUB 186-3), and SHA-384
 *
 *
 * SECRET LEVEL AES 128 ECDH and ECDSA using the 256-bit prime (FIPS PUB 186-3), and SHA-256. RSA with 2048 can be used for DH key
 * negotiation
 *
 *
 * WARNING! Note that this call is INCOMPATIBLE with GWT, so we have EXCLUDED IT from gwt, and created a CryptoGwt class in the web-client
 * project which only has the necessary crypto utility methods that are 1) Necessary 2) Compatible with GWT
 *
 *
 *
 *
 * To determine if we have hardware accelerated AES java -XX:+PrintFlagsFinal -version | grep UseAES
 *
 * Per NIST SP800-38D,
 * The total number of invocations of the authenticated encryption function shall not exceed 232, including all IV lengths and all instances of the authenticated encryption function with the given key.
 *
 */
object Crypto {
    /**
     * Gets the version number.
     */
    const val version = "1.3"

    init {
        // Add this project to the updates system, which verifies this class + UUID + version information
        add(Crypto::class.java, "61800355740c4f7ebfe9c0a57e4b6fb2", version)
    }

    // CUSTOM_HEADER USE
    // check to see if our extra data is OURS. if so, process it
    // cafeʞ, as UN signed bytes is: [254, 202, 202, 158], or as hex: FECA CA9E
    // cafeʞ, as signed bytes is: [-2, -54, -54, -98]
    private val CUSTOM_HEADER = byteArrayOf((-2).toByte(), (-54).toByte(), (-54).toByte(), (-98).toByte())

    fun addProvider() {
        // make sure we only add it once (in case it's added elsewhere...)
        val provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)
        if (provider == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /**
     * Determines if cryptography restrictions apply.
     * Restrictions apply if the value of [Cipher.getMaxAllowedKeyLength] returns a value smaller than [Integer.MAX_VALUE] if there are any restrictions according to the JavaDoc of the method.
     * This method is used with the transform `"AES/CBC/PKCS5Padding"` as this is an often used algorithm that is [an implementation requirement for Java SE](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#impl).
     *
     * @return `true` if restrictions apply, `false` otherwise
     */
    fun restrictedCryptography(): Boolean {
        return try {
            Cipher.getMaxAllowedKeyLength("AES/CBC/PKCS5Padding") < Int.MAX_VALUE
        } catch (e: NoSuchAlgorithmException) {
            throw IllegalStateException(
                "The transform \"AES/CBC/PKCS5Padding\" is not available (the availability of this algorithm is mandatory for Java SE implementations)",
                e
            )
        }
    }

    fun toInt(bytes: ByteArray): Int {
        var number = 0
        when (bytes.size) {
            4 -> {
                number = number or (bytes[3].toInt() and 0xFF shl 24)
                number = number or (bytes[2].toInt() and 0xFF shl 16)
                number = number or (bytes[1].toInt() and 0xFF shl 8)
                number = number or (bytes[0].toInt() and 0xFF shl 0)
            }

            3 -> {
                number = number or (bytes[2].toInt() and 0xFF shl 16)
                number = number or (bytes[1].toInt() and 0xFF shl 8)
                number = number or (bytes[0].toInt() and 0xFF shl 0)
            }

            2 -> {
                number = number or (bytes[1].toInt() and 0xFF shl 8)
                number = number or (bytes[0].toInt() and 0xFF shl 0)
            }

            1 -> number = number or (bytes[0].toInt() and 0xFF shl 0)
            else -> {
                number = number or (bytes[3].toInt() and 0xFF shl 24)
                number = number or (bytes[2].toInt() and 0xFF shl 16)
                number = number or (bytes[1].toInt() and 0xFF shl 8)
                number = number or (bytes[0].toInt() and 0xFF shl 0)
            }
        }
        return number
    }

    /**
     * Specifically, to return the hash of the ALL files/directories inside the jar, minus the action specified (LGPL) files.
     */
    @Throws(IOException::class)
    fun hashJarContentsExcludeAction(jarDestFilename: File?, digest: Digest, action: Int): ByteArray? {
        val jarDestFile = JarFile(jarDestFilename)
        try {
            val jarElements = jarDestFile.entries()
            var okToHash: Boolean
            var hasAction: Boolean
            val buffer = ByteArray(2048)
            var read: Int
            digest.reset()
            while (jarElements.hasMoreElements()) {
                val jarEntry = jarElements.nextElement()
                val name = jarEntry.name
                okToHash = !jarEntry.isDirectory
                if (!okToHash) {
                    continue
                }

                // data with NO extra data will NOT BE HASHED
                // data that matches our action bitmask WILL NOT BE HASHED
                okToHash = false
                hasAction = false
                val extraData = jarEntry.extra
                if (extraData == null || extraData.size == 0) {
                    okToHash = false
                } else if (extraData.size >= 4) {
                    for (i in CUSTOM_HEADER.indices) {
                        if (extraData[i] != CUSTOM_HEADER[i]) {
                            throw RuntimeException("Unexpected extra data in zip assigned. Aborting")
                        }
                    }

                    // this means we matched our header
                    if (extraData[4] > 0) {
                        hasAction = true

                        // we have an ACTION describing how it was compressed, etc
                        val fileAction = toInt(byteArrayOf(extraData[5], extraData[6], extraData[7], extraData[8]))
                        if (fileAction and action != action) {
                            okToHash = true
                        }
                    } else {
                        okToHash = true
                    }
                } else {
                    return null
                }

                // skips hashing lgpl files. (technically, whatever our action bitmask is...)
                // we want to hash everything BY DEFAULT. we ALSO want to hash the NAME, LOAD ACTION TYPE, and the contents
                if (okToHash) {
                    // System.err.println("HASHING: " + name);
                    // hash the file name
                    val bytes = name.toByteArray(StandardCharsets.US_ASCII)
                    digest.update(bytes, 0, bytes.size)
                    if (hasAction) {
                        // hash the action - since we don't want to permit anyone to change this after we sign the file
                        digest.update(extraData, 5, 4)
                    }

                    // hash the contents
                    val inputStream = jarDestFile.getInputStream(jarEntry)
                    while (inputStream.read(buffer).also { read = it } > 0) {
                        digest.update(buffer, 0, read)
                    }
                    inputStream.close()
                }
                //else {
                //    System.err.println("Skipping: " + name);
                //}
            }
        } catch (e: Exception) {
            e.printStackTrace()
            return null
        } finally {
            jarDestFile.close()
        }

        val digestBytes = ByteArray(digest.digestSize)
        digest.doFinal(digestBytes, 0)
        return digestBytes
    }

    /**
     * Secure way to generate an AES key based on a password. Will '*' out the passed-in password
     *
     * @param password
     * will be filled with '*'
     * @param salt
     * should be a RANDOM number, at least 256bits (32 bytes) in size.
     * @param iterationCount
     * should be a lot, like 10,000
     *
     * @return the secure key to use
     */
    fun PBKDF2(password: CharArray, salt: ByteArray, iterationCount: Int): ByteArray {
        // will also zero out the password.
        val charToBytes = charToBytesPassword_UTF16(password)
        return PBKDF2(charToBytes, salt, iterationCount)
    }

    /**
     * Secure way to generate an AES key based on a password.
     *
     * @param password The password that you want to mix
     * @param salt should be a RANDOM number, at least 256bits (32 bytes) in size.
     * @param iterationCount should be a lot, like 10,000
     *
     * @return the secure key to use
     */
    fun PBKDF2(password: ByteArray, salt: ByteArray, iterationCount: Int): ByteArray {
        val digest = SHA256Digest()
        val pGen: PBEParametersGenerator = PKCS5S2ParametersGenerator(digest)
        pGen.init(password, salt, iterationCount)
        val key = pGen.generateDerivedMacParameters(digest.digestSize * 8) as KeyParameter // *8 for bit length.

        // zero out the password.
        Arrays.fill(password, 0.toByte())
        return key.key
    }

    /**
     * this saves the char array in UTF-16 format of bytes and BLANKS out the password char array.
     */
    fun charToBytesPassword_UTF16(password: CharArray): ByteArray {
        // note: this saves the char array in UTF-16 format of bytes.
        val passwordBytes = ByteArray(password.size * 2)
        for (i in password.indices) {
            passwordBytes[2 * i] = (password[i].code and 0xFF00 shr 8).toByte()
            passwordBytes[2 * i + 1] = (password[i].code and 0x00FF).toByte()
        }

        // asterisk out the password
        Arrays.fill(password, '*')
        return passwordBytes
    }
}
