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

import org.bouncycastle.crypto.generators.SCrypt
import org.bouncycastle.util.encoders.Base64

import java.util.*

/**
 * An implementation of the [](http://www.tarsnap.com/scrypt/scrypt.pdf)scrypt
 * key derivation function. The following is based on the bouncycastle crypto package and examples
 */
object SCrypt {
    /**
     * Gets the version number.
     */
    val version = Crypto.version

    private val splitRegex = "\\$".toRegex()

    /**
     * Converts a char array to a UTF-16 format byte array.
     */
    private fun charToBytes(password: CharArray): ByteArray {
        val passwordBytes = ByteArray(password.size * 2)
        for (i in password.indices) {
            passwordBytes[2 * i] = (password[i].code and 0xFF00 shr 8).toByte()
            passwordBytes[2 * i + 1] = (password[i].code and 0x00FF).toByte()
        }
        return passwordBytes
    }

    /**
     * Hash the supplied plaintext password and generate output using default parameters
     *
     *
     * The password chars are no longer valid after this call
     *
     * @param password  Password.
     * @param salt      Salt parameter
     */
    fun encrypt(password: String, salt: ByteArray): String {
        return encrypt(password.toCharArray(), salt, 16384, 32, 1, 64)
    }
    /**
     * Hash the supplied plaintext password and generate output.
     *
     *
     * The password chars are no longer valid after this call
     *
     * @param password  Password.
     * @param salt      Salt parameter
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     *
     * @return The hashed password.
     */
    fun encrypt(password: CharArray, salt: ByteArray, N: Int = 16384, r: Int = 32, p: Int = 1, dkLen: Int = 64): String {
        // Note: this saves the char array in UTF-16 format of bytes.
        val passwordBytes: ByteArray = charToBytes(password)

        require(!(N == 0 || N and N - 1 != 0)) { "N must be > 0 and a power of 2" }
        require(N <= Int.MAX_VALUE / 128 / r) { "Parameter N is too large" }
        require(r <= Int.MAX_VALUE / 128 / p) { "Parameter r is too large" }

        val derived = SCrypt.generate(passwordBytes, salt, N, r, p, dkLen)
        val params = Integer.toString(log2(N) shl 16 or (r shl 8) or p, 16)

        val sb = StringBuilder((salt.size + derived.size) * 2)
        sb.append("\$s0$").append(params).append('$')
        sb.append(String(Base64.encode(salt))).append('$')
        sb.append(String(Base64.encode(derived)))
        return sb.toString()
    }

    /**
     * Pure Java implementation of the [](http://www.tarsnap.com/scrypt/scrypt.pdf)scrypt KDF.
     *
     * @param password  Password.
     * @param salt      Salt.
     * @param N         CPU cost parameter.
     * @param r         Memory cost parameter.
     * @param p         Parallelization parameter.
     * @param dkLen     Intended length of the derived key.
     *
     * @return The derived key.
     */
    fun encrypt(password: ByteArray, salt: ByteArray, N: Int, r: Int, p: Int, dkLen: Int): ByteArray {
        require(!(N == 0 || N and N - 1 != 0)) { "N must be > 0 and a power of 2" }
        require(N <= Int.MAX_VALUE / 128 / r) { "Parameter N is too large" }
        require(r <= Int.MAX_VALUE / 128 / p) { "Parameter r is too large" }

        return try {
            SCrypt.generate(password, salt, N, r, p, dkLen)
        } finally {
            // now zero out the bytes in password.
            Arrays.fill(password, 0.toByte())
        }
    }

    /**
     * Compare the supplied plaintext password to a hashed password.
     *
     * @param   password  Plaintext password.
     * @param   hashedPassword  scrypt hashed password.
     *
     * @return true if password matches hashed value.
     */
    fun verify(password: String, hashedPassword: String): Boolean {
        return verify(password.toCharArray(), hashedPassword)
    }

    /**
     * Compare the supplied plaintext password to a hashed password.
     *
     * @param   password  Plaintext password.
     * @param   hashedPassword  scrypt hashed password.
     *
     * @return true if password matches hashed value.
     */
    fun verify(password: CharArray, hashedPassword: String): Boolean {
        val passwordBytes = charToBytes(password)

        val parts = hashedPassword.split(splitRegex).dropLastWhile { it.isEmpty() }.toTypedArray()
        if (parts.size != 5 || parts[1] != "s0") {
            return false
        }
        val params = parts[2].toInt(16)
        val salt: ByteArray = Base64.decode(parts[3])
        val derived0: ByteArray = Base64.decode(parts[4])

        val N = Math.pow(2.0, (params shr 16 and 0xff).toDouble()).toInt()
        val r = params shr 8 and 0xff
        val p = params and 0xff
        val dkLen = derived0.size
        val derived1 = SCrypt.generate(passwordBytes, salt, N, r, p, dkLen)
        if (derived0.size != derived1.size) {
            return false
        }

        var result = 0
        for (i in derived0.indices) {
            result = result or (derived0[i].toInt() xor derived1[i].toInt())
        }

        return result == 0
    }

    private fun log2(n: Int): Int {
        var n = n
        var log = 0
        if (n and -0x10000 != 0) {
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
}
