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

import dorkbox.crypto.CryptoAES.decrypt
import dorkbox.crypto.CryptoAES.decryptStream
import dorkbox.crypto.CryptoAES.decryptStreamWithIV
import dorkbox.crypto.CryptoAES.decryptWithIV
import dorkbox.crypto.CryptoAES.encrypt
import dorkbox.crypto.CryptoAES.encryptStream
import dorkbox.crypto.CryptoAES.encryptStreamWithIV
import dorkbox.crypto.CryptoAES.encryptWithIV
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.engines.AESFastEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.junit.Assert
import org.junit.Test
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.SecureRandom

class AesTest {
    var logger: Logger? = LoggerFactory.getLogger(this.javaClass)

    @Test
    @Throws(IOException::class)
    fun AesGcm() {
        val bytes = "hello, my name is inigo montoya".toByteArray()

        val rand = SecureRandom(entropySeed.toByteArray())

        val aesEngine = GCMBlockCipher(AESEngine())

        val key = ByteArray(32)
        val iv = ByteArray(16)

        // note: the IV needs to be VERY unique!
        rand.nextBytes(key) // 256bit key (32 bytes)
        rand.nextBytes(iv) // 128bit block size (16 bytes)


        val encryptAES = encrypt(aesEngine, key, iv, bytes, logger)
        val decryptAES = decrypt(aesEngine, key, iv, encryptAES, logger)

        if (bytes.contentEquals(encryptAES)) {
            Assert.fail("bytes should not be equal")
        }

        if (!bytes.contentEquals(decryptAES)) {
            Assert.fail("bytes not equal")
        }
    }

    // Note: this is still tested, but DO NOT USE BLOCK MODE as it does NOT provide authentication. GCM does.
    @Suppress("deprecation")
    @Test
    @Throws(IOException::class)
    fun AesBlock() {
        val bytes = "hello, my name is inigo montoya".toByteArray()

        val rand = SecureRandom(entropySeed.toByteArray())

        val aesEngine = PaddedBufferedBlockCipher(CBCBlockCipher(AESFastEngine()))

        val key = ByteArray(32)
        val iv = ByteArray(16)

        // note: the IV needs to be VERY unique!
        rand.nextBytes(key) // 256bit key
        rand.nextBytes(iv) // 16bit block size


        val encryptAES = encrypt(aesEngine, key, iv, bytes, logger)
        val decryptAES = decrypt(aesEngine, key, iv, encryptAES, logger)

        if (bytes.contentEquals(encryptAES)) {
            Assert.fail("bytes should not be equal")
        }

        if (!bytes.contentEquals(decryptAES)) {
            Assert.fail("bytes not equal")
        }
    }

    @Test
    @Throws(IOException::class)
    fun AesGcmStream() {
        val originalBytes = "hello, my name is inigo montoya".toByteArray()
        var inputStream = ByteArrayInputStream(originalBytes)
        var outputStream = ByteArrayOutputStream()

        val rand = SecureRandom(entropySeed.toByteArray())

        val aesEngine = GCMBlockCipher(AESEngine())

        val key = ByteArray(32)
        val iv = ByteArray(16)

        // note: the IV needs to be VERY unique!
        rand.nextBytes(key) // 256bit key
        rand.nextBytes(iv) // 128bit block size


        var success = encryptStream(aesEngine, key, iv, inputStream, outputStream, logger)

        if (!success) {
            Assert.fail("crypto was not successful")
        }

        val encryptBytes = outputStream.toByteArray()

        inputStream = ByteArrayInputStream(outputStream.toByteArray())
        outputStream = ByteArrayOutputStream()

        success = decryptStream(aesEngine, key, iv, inputStream, outputStream, logger)

        if (!success) {
            Assert.fail("crypto was not successful")
        }

        val decryptBytes = outputStream.toByteArray()

        if (originalBytes.contentEquals(encryptBytes)) {
            Assert.fail("bytes should not be equal")
        }

        if (!originalBytes.contentEquals(decryptBytes)) {
            Assert.fail("bytes not equal")
        }
    }

    // Note: this is still tested, but DO NOT USE BLOCK MODE as it does NOT provide authentication. GCM does.
    @Suppress("deprecation")
    @Test
    @Throws(IOException::class)
    fun AesBlockStream() {
        val originalBytes = "hello, my name is inigo montoya".toByteArray()
        var inputStream = ByteArrayInputStream(originalBytes)
        var outputStream = ByteArrayOutputStream()

        val rand = SecureRandom(entropySeed.toByteArray())

        val aesEngine = PaddedBufferedBlockCipher(CBCBlockCipher(AESFastEngine()))

        val key = ByteArray(32)
        val iv = ByteArray(16)

        // note: the IV needs to be VERY unique!
        rand.nextBytes(key) // 256bit key
        rand.nextBytes(iv) // 128bit block size


        var success = encryptStream(aesEngine, key, iv, inputStream, outputStream, logger)

        if (!success) {
            Assert.fail("crypto was not successful")
        }

        val encryptBytes = outputStream.toByteArray()

        inputStream = ByteArrayInputStream(outputStream.toByteArray())
        outputStream = ByteArrayOutputStream()

        success = decryptStream(aesEngine, key, iv, inputStream, outputStream, logger)


        if (!success) {
            Assert.fail("crypto was not successful")
        }

        val decryptBytes = outputStream.toByteArray()

        if (originalBytes.contentEquals(encryptBytes)) {
            Assert.fail("bytes should not be equal")
        }

        if (!originalBytes.contentEquals(decryptBytes)) {
            Assert.fail("bytes not equal")
        }
    }

    @Test
    @Throws(IOException::class)
    fun AesWithIVGcm() {
        val bytes = "hello, my name is inigo montoya".toByteArray()

        val rand = SecureRandom(entropySeed.toByteArray())

        val aesEngine = GCMBlockCipher(AESEngine())

        val key = ByteArray(32) // 256bit key
        val iv = ByteArray(aesEngine.getUnderlyingCipher().getBlockSize())

        // note: the IV needs to be VERY unique!
        rand.nextBytes(key)
        rand.nextBytes(iv)


        val encryptAES = encryptWithIV(aesEngine, key, iv, bytes, logger)
        val decryptAES = decryptWithIV(aesEngine, key, encryptAES, logger)

        if (bytes.contentEquals(encryptAES)) {
            Assert.fail("bytes should not be equal")
        }

        if (!bytes.contentEquals(decryptAES)) {
            Assert.fail("bytes not equal")
        }
    }

    // Note: this is still tested, but DO NOT USE BLOCK MODE as it does NOT provide authentication. GCM does.
    @Suppress("deprecation")
    @Test
    @Throws(IOException::class)
    fun AesWithIVBlock() {
        val bytes = "hello, my name is inigo montoya".toByteArray()

        val rand = SecureRandom(entropySeed.toByteArray())

        val aesEngine = PaddedBufferedBlockCipher(CBCBlockCipher(AESFastEngine()))

        val key = ByteArray(32) // 256bit key
        val iv = ByteArray(aesEngine.getUnderlyingCipher().getBlockSize())

        // note: the IV needs to be VERY unique!
        rand.nextBytes(key)
        rand.nextBytes(iv)


        val encryptAES = encryptWithIV(aesEngine, key, iv, bytes, logger)
        val decryptAES = decryptWithIV(aesEngine, key, encryptAES, logger)

        if (bytes.contentEquals(encryptAES)) {
            Assert.fail("bytes should not be equal")
        }

        if (!bytes.contentEquals(decryptAES)) {
            Assert.fail("bytes not equal")
        }
    }

    @Test
    @Throws(IOException::class)
    fun AesWithIVGcmStream() {
        val originalBytes = "hello, my name is inigo montoya".toByteArray()
        var inputStream = ByteArrayInputStream(originalBytes)
        var outputStream = ByteArrayOutputStream()

        val rand = SecureRandom(entropySeed.toByteArray())

        val aesEngine = GCMBlockCipher(AESEngine())

        val key = ByteArray(32)
        val iv = ByteArray(16)

        // note: the IV needs to be VERY unique!
        rand.nextBytes(key) // 256bit key
        rand.nextBytes(iv) // 128bit block size


        var success = encryptStreamWithIV(aesEngine, key, iv, inputStream, outputStream, logger)

        if (!success) {
            Assert.fail("crypto was not successful")
        }

        val encryptBytes = outputStream.toByteArray()

        inputStream = ByteArrayInputStream(outputStream.toByteArray())
        outputStream = ByteArrayOutputStream()

        success = decryptStreamWithIV(aesEngine, key, inputStream, outputStream, logger)

        if (!success) {
            Assert.fail("crypto was not successful")
        }

        val decryptBytes = outputStream.toByteArray()

        if (originalBytes.contentEquals(encryptBytes)) {
            Assert.fail("bytes should not be equal")
        }

        if (!originalBytes.contentEquals(decryptBytes)) {
            Assert.fail("bytes not equal")
        }
    }

    // Note: this is still tested, but DO NOT USE BLOCK MODE as it does NOT provide authentication. GCM does.
    @Suppress("deprecation")
    @Test
    @Throws(IOException::class)
    fun AesWithIVBlockStream() {
        val originalBytes = "hello, my name is inigo montoya".toByteArray()
        var inputStream = ByteArrayInputStream(originalBytes)
        var outputStream = ByteArrayOutputStream()

        val rand = SecureRandom(entropySeed.toByteArray())

        val aesEngine = PaddedBufferedBlockCipher(CBCBlockCipher(AESFastEngine()))

        val key = ByteArray(32)
        val iv = ByteArray(16)

        // note: the IV needs to be VERY unique!
        rand.nextBytes(key) // 256bit key
        rand.nextBytes(iv) // 128bit block size


        var success = encryptStreamWithIV(aesEngine, key, iv, inputStream, outputStream, logger)

        if (!success) {
            Assert.fail("crypto was not successful")
        }

        val encryptBytes = outputStream.toByteArray()

        inputStream = ByteArrayInputStream(outputStream.toByteArray())
        outputStream = ByteArrayOutputStream()

        success = decryptStreamWithIV(aesEngine, key, inputStream, outputStream, logger)


        if (!success) {
            Assert.fail("crypto was not successful")
        }

        val decryptBytes = outputStream.toByteArray()

        if (originalBytes.contentEquals(encryptBytes)) {
            Assert.fail("bytes should not be equal")
        }

        if (!originalBytes.contentEquals(decryptBytes)) {
            Assert.fail("bytes not equal")
        }
    }

    companion object {
        private const val entropySeed = "asdjhasdkljalksdfhlaks4356268909087s0dfgkjh255124515hasdg87"
    }
}
