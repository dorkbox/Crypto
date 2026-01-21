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

import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.lang.Byte
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.ShortBufferException
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.Array
import kotlin.Boolean
import kotlin.ByteArray
import kotlin.Exception
import kotlin.Long
import kotlin.String
import kotlin.Throws

// See: https://stackoverflow.com/questions/25992131/slow-aes-gcm-encryption-and-decryption-with-java-8u20
// java8 performance is 3 MB/s. BC is ~43 MB/s
object PerformanceTest {
    private const val entropySeed = "asdjhasdkljalksdfhlaks4356268909087s0dfgkjh255124515hasdg87"

    @Throws(Exception::class)
    @JvmStatic
    fun main(args: Array<String>) {
        val max = 5
        for (i in 0..<max) {
            println("Warming up " + (i + 1) + " of " + max)
            BC_Test(true)
            Java_Test(true)
        }
        BC_Test(false)
        Java_Test(false)
    }

    fun BC_Test(isWarmup: Boolean) {
        val bytes = ByteArray(64 * 1024)
        var encrypted: ByteArray? = null
        val aesKey = ByteArray(32)
        val aesIV = ByteArray(12)

        val random: Random = SecureRandom(entropySeed.toByteArray())
        random.nextBytes(bytes)
        random.nextBytes(aesKey)
        random.nextBytes(aesIV)

        var length = bytes.size

        if (!isWarmup) {
            println("Benchmarking AES-256 GCM BOUNCYCASTLE encryption")
        }

        var javaEncryptInputBytes: Long = 0
        val javaEncryptStartTime = System.currentTimeMillis()

        // convert to bouncycastle
        val aesIVAndKey: CipherParameters = ParametersWithIV(KeyParameter(aesKey), aesIV)

        var encryptInitTime = 0L
        var encryptUpdate1Time = 0L
        var encryptDoFinalTime = 0L

        while (System.currentTimeMillis() - javaEncryptStartTime < 10000) {
            random.nextBytes(aesIV)

            val n1 = System.nanoTime()

            val aesEngine = GCMBlockCipher(AESEngine())
            aesEngine.reset()
            aesEngine.init(true, aesIVAndKey)

            if (encrypted == null) {
                val minSize = aesEngine.getOutputSize(length)
                encrypted = ByteArray(minSize)
            }

            val n2 = System.nanoTime()
            var actualLength = aesEngine.processBytes(bytes, 0, length, encrypted, 0)

            val n3 = System.nanoTime()
            try {
                actualLength += aesEngine.doFinal(encrypted, actualLength)
            }
            catch (e: Exception) {
                e.printStackTrace()
                System.err.println("Unable to perform AES cipher.")
            }

            if (encrypted.size != actualLength) {
                val result = ByteArray(actualLength)
                System.arraycopy(encrypted, 0, result, 0, result.size)
                encrypted = result
            }

            val n4 = System.nanoTime()

            javaEncryptInputBytes += actualLength.toLong()

            encryptInitTime = n2 - n1
            encryptUpdate1Time = n3 - n2
            encryptDoFinalTime = n4 - n3
        }

        val javaEncryptEndTime = System.currentTimeMillis()

        if (!isWarmup) {
            println("Time init (ns): " + encryptInitTime)
            println("Time update (ns): " + encryptUpdate1Time)
            println("Time do final (ns): " + encryptDoFinalTime)
            println(
                "Java calculated at " + (javaEncryptInputBytes / 1024 / 1024 / ((javaEncryptEndTime - javaEncryptStartTime) / 1000)) + " MB/s"
            )
        }


        if (!isWarmup) {
            println("Benchmarking AES-256 GCM BOUNCYCASTLE de-encryption")
        }

        var javaDecryptInputBytes: Long = 0
        val javaDecryptStartTime = System.currentTimeMillis()

        length = encrypted!!.size

        var decryptInitTime = 0L
        var decryptUpdate1Time = 0L
        var decryptDoFinalTime = 0L

        while (System.currentTimeMillis() - javaDecryptStartTime < 10000) {
            val n1 = System.nanoTime()

            val aesEngine = GCMBlockCipher(AESEngine())
            aesEngine.reset()
            aesEngine.init(false, aesIVAndKey)

            val n2 = System.nanoTime()

            var actualLength = aesEngine.processBytes(encrypted, 0, length, bytes, 0)

            val n3 = System.nanoTime()

            try {
                actualLength += aesEngine.doFinal(bytes, actualLength)
            }
            catch (e: Exception) {
                e.printStackTrace()
                System.err.println("Unable to perform AES cipher.")
            }


            val n4 = System.nanoTime()

            javaDecryptInputBytes += actualLength.toLong()

            decryptInitTime += n2 - n1
            decryptUpdate1Time += n3 - n2
            decryptDoFinalTime += n4 - n3
        }
        val javaDecryptEndTime = System.currentTimeMillis()

        if (!isWarmup) {
            println("Time init (ns): " + decryptInitTime)
            println("Time update 1 (ns): " + decryptUpdate1Time)
            println("Time do final (ns): " + decryptDoFinalTime)
            println("Total bytes processed: " + javaDecryptInputBytes)
            println(
                "Java calculated at " + (javaDecryptInputBytes / 1024 / 1024 / ((javaDecryptEndTime - javaDecryptStartTime) / 1000)) + " MB/s"
            )
        }
    }

    @Throws(
        NoSuchPaddingException::class,
        NoSuchAlgorithmException::class,
        InvalidAlgorithmParameterException::class,
        InvalidKeyException::class,
        ShortBufferException::class
    )
    fun Java_Test(isWarmup: Boolean) {
        val bytes = ByteArray(64 * 1024)
        var encrypted: ByteArray? = null
        val aesKey = ByteArray(32)
        val aesIV = ByteArray(12)

        val random: Random = SecureRandom(entropySeed.toByteArray())
        random.nextBytes(bytes)
        random.nextBytes(aesKey)
        random.nextBytes(aesIV)

        var length = bytes.size

        if (!isWarmup) {
            println("Benchmarking AES-256 GCM JVM encryption")
        }

        var javaEncryptInputBytes: Long = 0
        val javaEncryptStartTime = System.currentTimeMillis()

        val javaAES256 = Cipher.getInstance("AES/GCM/NoPadding")

        var encryptInitTime = 0L
        var encryptUpdate1Time = 0L
        var encryptDoFinalTime = 0L

        while (System.currentTimeMillis() - javaEncryptStartTime < 10000) {
            random.nextBytes(aesIV)

            val n1 = System.nanoTime()

            javaAES256.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"), GCMParameterSpec(16 * Byte.SIZE, aesIV))

            if (encrypted == null) {
                val minSize = javaAES256.getOutputSize(length)
                encrypted = ByteArray(minSize)
            }

            val n2 = System.nanoTime()
            var actualLength = javaAES256.update(bytes, 0, bytes.size, encrypted, 0)

            val n3 = System.nanoTime()
            try {
                actualLength += javaAES256.doFinal(encrypted, actualLength)
            }
            catch (e: Exception) {
                e.printStackTrace()
                System.err.println("Unable to perform AES cipher.")
            }

            if (encrypted.size != actualLength) {
                val result = ByteArray(actualLength)
                System.arraycopy(encrypted, 0, result, 0, result.size)
                encrypted = result
            }

            val n4 = System.nanoTime()

            javaEncryptInputBytes += actualLength.toLong()

            encryptInitTime = n2 - n1
            encryptUpdate1Time = n3 - n2
            encryptDoFinalTime = n4 - n3
        }

        val javaEncryptEndTime = System.currentTimeMillis()

        if (!isWarmup) {
            println("Time init (ns): " + encryptInitTime)
            println("Time update (ns): " + encryptUpdate1Time)
            println("Time do final (ns): " + encryptDoFinalTime)
            println(
                "Java calculated at " + (javaEncryptInputBytes / 1024 / 1024 / ((javaEncryptEndTime - javaEncryptStartTime) / 1000)) + " MB/s"
            )

            println("Benchmarking AES-256 GCM decryption")
        }

        if (!isWarmup) {
            println("Benchmarking AES-256 GCM JVM de-encryption")
        }


        var javaDecryptInputBytes: Long = 0
        val javaDecryptStartTime = System.currentTimeMillis()

        val gcmParameterSpec = GCMParameterSpec(16 * Byte.SIZE, aesIV)
        val keySpec = SecretKeySpec(aesKey, "AES")


        length = encrypted!!.size

        var decryptInitTime = 0L
        var decryptUpdate1Time = 0L
        var decryptDoFinalTime = 0L

        while (System.currentTimeMillis() - javaDecryptStartTime < 10000) {
            val n1 = System.nanoTime()

            javaAES256.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec)

            val n2 = System.nanoTime()

            var actualLength = javaAES256.update(encrypted, 0, length, bytes, 0)

            val n3 = System.nanoTime()

            try {
                actualLength += javaAES256.doFinal(bytes, actualLength)
            }
            catch (e: Exception) {
                e.printStackTrace()
                System.err.println("Unable to perform AES cipher.")
            }


            val n4 = System.nanoTime()

            javaDecryptInputBytes += actualLength.toLong()

            decryptInitTime += n2 - n1
            decryptUpdate1Time += n3 - n2
            decryptDoFinalTime += n4 - n3
        }
        val javaDecryptEndTime = System.currentTimeMillis()

        if (!isWarmup) {
            println("Time init (ns): " + decryptInitTime)
            println("Time update 1 (ns): " + decryptUpdate1Time)
            println("Time do final (ns): " + decryptDoFinalTime)
            println("Total bytes processed: " + javaDecryptInputBytes)
            println(
                "Java calculated at " + (javaDecryptInputBytes / 1024 / 1024 / ((javaDecryptEndTime - javaDecryptStartTime) / 1000)) + " MB/s"
            )
        }
    }
}
