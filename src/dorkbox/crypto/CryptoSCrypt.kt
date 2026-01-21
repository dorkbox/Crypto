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

import dorkbox.crypto.Crypto.charToBytesPassword_UTF16
import org.bouncycastle.crypto.generators.SCrypt
import java.security.SecureRandom
import java.util.*
import kotlin.math.pow

/**
 * An implementation of the [](http://www.tarsnap.com/scrypt/scrypt.pdf) scrypt key derivation function.
 */
object CryptoSCrypt {
    /**
     * Gets the version number.
     */
    const val version = Crypto.version

    /**
     * Hash the supplied plaintext password and generate output.
     * 
     * 
     * The password chars are no longer valid after this call
     * 
     * @param password Password.
     * @param n CPU cost parameter.
     * @param r Memory cost parameter.
     * @param p Parallelization parameter.
     * 
     * @return The hashed password.
     */
    fun encrypt(password: CharArray, n: Int = 16384, r: Int = 32, p: Int = 1): String {
        val secureRandom = SecureRandom()
        val salt = ByteArray(32)
        secureRandom.nextBytes(salt)

        return encrypt(password, salt, n, r, p, 64)
    }

    /**
     * Hash the supplied plaintext password and generate output.
     * 
     * 
     * The password chars are no longer valid after this call
     * 
     * @param password Password.
     * @param salt Salt parameter
     * @param n CPU cost parameter.
     * @param r Memory cost parameter.
     * @param p Parallelization parameter.
     * @param dkLen Intended length of the derived key.
     * 
     * @return The hashed password.
     */
    fun encrypt(password: CharArray, salt: ByteArray, n: Int = 16384, r: Int = 128, p: Int = 1, dkLen: Int = 64): String {
        // Note: this saves the char array in UTF-16 format of bytes.
        // can't use password after this as it's been changed to '*'
        val passwordBytes = charToBytesPassword_UTF16(password)

        val derived = encrypt(passwordBytes, salt, n, r, p, dkLen)

        val params = (log2(n) shl 16 or (r shl 8) or p).toString(16)

        val sb = StringBuilder((salt.size + derived.size) * 2)
        sb.append("\$s0$").append(params).append('$')
        sb.append(Base64.getEncoder().encodeToString(salt)).append('$')
        sb.append(Base64.getEncoder().encodeToString(derived))

        return sb.toString()
    }

    /**
     * Compare the supplied plaintext password to a hashed password.
     * 
     * @param password Plaintext password.
     * @param hashed scrypt hashed password.
     * 
     * @return true if password matches hashed value.
     */
    fun verify(password: CharArray, hashed: String): Boolean {
        // Note: this saves the char array in UTF-16 format of bytes.
        // can't use password after this as it's been changed to '*'
        val passwordBytes = charToBytesPassword_UTF16(password)

        val parts: Array<String?> = hashed.split("\\$".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()

        require(!(parts.size != 5 || parts[1] != "s0")) { "Invalid hashed value" }

        val params = parts[2]!!.toInt(16)
        val salt = Base64.getDecoder().decode(parts[3])
        val derived0 = Base64.getDecoder().decode(parts[4])

        val n = 2.0.pow((params shr 16 and 0xFF).toDouble()).toInt()
        val r = params shr 8 and 0xFF
        val p = params and 0xFF

        val length = derived0.size
        if (length == 0) {
            return false
        }

        val derived1 = encrypt(passwordBytes, salt, n, r, p, length)

        if (length != derived1.size) {
            return false
        }

        var result = 0
        for (i in 0..<length) {
            result = result or (derived0[i].toInt() xor derived1[i].toInt())
        }

        return result == 0
    }

    private fun log2(n: Int): Int {
        var n = n
        var log = 0
        if ((n and -0x10000) != 0) {
            n = n ushr 16
            log = 16
        }
        if (n >= 256) {
            n = n ushr 8
            log += 8
        }
        if (n >= 16) {
            n = n ushr 4
            log += 4
        }
        if (n >= 4) {
            n = n ushr 2
            log += 2
        }
        return log + (n ushr 1)
    }

    /**
     * Pure Java implementation of the [](http://www.tarsnap.com/scrypt/scrypt.pdf)scrypt KDF.
     * 
     * @param password Password.
     * @param salt Salt.
     * @param n CPU cost parameter.
     * @param r Memory cost parameter.
     * @param p  Parallelization parameter.
     * @param dkLen Intended length of the derived key.
     * 
     * @return The derived key.
     */
    fun encrypt(password: ByteArray, salt: ByteArray, n: Int, r: Int, p: Int, dkLen: Int): ByteArray {
        require(!(n == 0 || (n and n - 1) != 0)) { "n must be > 0 and a power of 2" }

        require(n <= Int.MAX_VALUE / 128 / r) { "Parameter n is too large" }
        require(r <= Int.MAX_VALUE / 128 / p) { "Parameter r is too large" }

        try {
            return SCrypt.generate(password, salt, n, r, p, dkLen)
        }
        finally {
            // now zero out the bytes in password.
            Arrays.fill(password, 0.toByte())
        }
    }
}
