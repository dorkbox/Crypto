/*
 * Copyright 2023 dorkbox, llc
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

import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


// https://stackoverflow.com/questions/11783062/how-to-decrypt-file-in-java-encrypted-with-openssl-command-using-aes/11786924#11786924
internal object OpenSSLPBECommon {
    /**
     * Gets the version number.
     */
    val version = Crypto.version


    const val SALT_SIZE_BYTES = 8
    const val OPENSSL_HEADER_STRING = "Salted__"
    val OPENSSL_HEADER_STRING_BYTES = OPENSSL_HEADER_STRING.toByteArray(Charsets.US_ASCII)

    private val hashDigest = MessageDigest.getInstance("SHA-256")

    fun toByteArray(chars: CharArray): ByteArray {
        val bytes = ByteArray(chars.size)

        for (i in bytes.indices) {
            bytes[i] = chars[i].code.toByte()
        }

        return bytes
    }

    @Throws(NoSuchAlgorithmException::class,
            InvalidKeySpecException::class,
            InvalidKeyException::class,
            NoSuchPaddingException::class,
            InvalidAlgorithmParameterException::class
           )
    fun initializeCipher(password: String, salt: ByteArray, cipherMode: Int): Cipher {
        val passwordBytes = password.toByteArray(Charsets.US_ASCII)

        hashDigest.update(passwordBytes)
        hashDigest.update(salt)

        var hash = hashDigest.digest()
        var keyAndIV = hash.clone()

        // 1 round
        hashDigest.update(hash)
        hashDigest.update(passwordBytes)
        hashDigest.update(salt)

        hash = hashDigest.digest()
        keyAndIV = concat(keyAndIV, hash)

        val keyBytes = keyAndIV.copyOfRange(0, 32)
        val ivBytes = keyAndIV.copyOfRange(32, 48)

        val key = SecretKeySpec(keyBytes, "AES")
        val iv = IvParameterSpec(ivBytes)


        val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
        cipher.init(cipherMode, key, iv);

        return cipher
    }

    private
    fun concat(a: ByteArray, b: ByteArray): ByteArray {
        val c = ByteArray(a.size + b.size)
        System.arraycopy(a, 0, c, 0, a.size)
        System.arraycopy(b, 0, c, a.size, b.size)
        return c
    }
}
