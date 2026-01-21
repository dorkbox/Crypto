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

import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.slf4j.Logger
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/**
 * AES crypto functions
 */
object CryptoAES {
    /**
     * Gets the version number.
     */
    const val version = Crypto.version

    private const val ivSize = 16

    /**
     * AES encrypts data with a specified key.
     * 
     * @param aesIV must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    fun encryptWithIV(aesEngine: GCMBlockCipher, aesKey: ByteArray, aesIV: ByteArray, data: ByteArray, logger: Logger? = null): ByteArray {
        val encryptAES = encrypt(aesEngine, aesKey, aesIV, data, logger)

        val length = encryptAES.size

        val out = ByteArray(length + ivSize)
        System.arraycopy(aesIV, 0, out, 0, ivSize)
        System.arraycopy(encryptAES, 0, out, ivSize, length)

        return out
    }

    /**
     * **CONVENIENCE METHOD ONLY - DO NOT USE UNLESS YOU HAVE TO**
     * 
     * 
     * Use GCM instead, as it's an authenticated cipher (and "regular" AES is not). This prevents tampering with the blocks of encrypted
     * data.
     * 
     * 
     * AES encrypts data with a specified key.
     * 
     * @param aesIV must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    @Deprecated("Use GCM instead")
    fun encryptWithIV(aesEngine: BufferedBlockCipher, aesKey: ByteArray, aesIV: ByteArray, data: ByteArray, logger: Logger? = null): ByteArray {
        val encryptAES = encrypt(aesEngine, aesKey, aesIV, data, logger)

        val length = encryptAES.size

        val out = ByteArray(length + ivSize)
        System.arraycopy(aesIV, 0, out, 0, ivSize)
        System.arraycopy(encryptAES, 0, out, ivSize, length)

        return out
    }

    /**
     * AES encrypts data with a specified key.
     * 
     * @param aesIV must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return true if successful
     */
    fun encryptStreamWithIV(
        aesEngine: GCMBlockCipher,
        aesKey: ByteArray,
        aesIV: ByteArray,
        `in`: InputStream,
        out: OutputStream,
        logger: Logger? = null
    ): Boolean {
        try {
            out.write(aesIV)
        }
        catch (e: IOException) {
            logger?.error("Unable to perform AES cipher.", e)
            return false
        }

        return encryptStream(aesEngine, aesKey, aesIV, `in`, out, logger)
    }

    /**
     * **CONVENIENCE METHOD ONLY - DO NOT USE UNLESS YOU HAVE TO**
     * 
     * 
     * Use GCM instead, as it's an authenticated cipher (and "regular" AES is not). This prevents tampering with the blocks of encrypted
     * data.
     * 
     * 
     * AES encrypts data with a specified key.
     * 
     * @param aesIV must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return true if successful
     */
    @Deprecated("Use GCM instead")
    fun encryptStreamWithIV(
        aesEngine: BufferedBlockCipher,
        aesKey: ByteArray,
        aesIV: ByteArray,
        `in`: InputStream,
        out: OutputStream,
        logger: Logger?
    ): Boolean {
        try {
            out.write(aesIV)
        }
        catch (e: IOException) {
            logger?.error("Unable to perform AES cipher.", e)
            return false
        }

        return encryptStream(aesEngine, aesKey, aesIV, `in`, out, logger)
    }

    /**
     * AES encrypts data with a specified key.
     * 
     * @param aesIV must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    fun encrypt(aesEngine: GCMBlockCipher, aesKey: ByteArray, aesIV: ByteArray, data: ByteArray, logger: Logger? = null): ByteArray {
        val length = data.size

        val aesIVAndKey: CipherParameters = ParametersWithIV(KeyParameter(aesKey), aesIV)
        return encrypt(aesEngine, aesIVAndKey, data, length, logger)
    }

    /**
     * AES encrypts data with a specified key.
     * 
     * @param logger may be null, if no log output is necessary
     * 
     * @return length of encrypted data, -1 if there was an error.
     */
    fun encrypt(aesEngine: GCMBlockCipher, aesIVAndKey: CipherParameters?, data: ByteArray, length: Int, logger: Logger? = null): ByteArray {
        aesEngine.reset()
        aesEngine.init(true, aesIVAndKey)

        val minSize = aesEngine.getOutputSize(length)
        val outArray = ByteArray(minSize)

        var actualLength = aesEngine.processBytes(data, 0, length, outArray, 0)

        try {
            actualLength += aesEngine.doFinal(outArray, actualLength)
        }
        catch (e: Exception) {
            logger?.error("Unable to perform AES cipher.", e)
            return ByteArray(0)
        }

        if (outArray.size == actualLength) {
            return outArray
        }
        else {
            val result = ByteArray(actualLength)
            System.arraycopy(outArray, 0, result, 0, result.size)
            return result
        }
    }

    /**
     * **CONVENIENCE METHOD ONLY - DO NOT USE UNLESS YOU HAVE TO**
     * 
     * 
     * Use GCM instead, as it's an authenticated cipher (and "regular" AES is not). This prevents tampering with the blocks of encrypted
     * data.
     * 
     * 
     * AES encrypts data with a specified key.
     * 
     * @param aesIV must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    @Deprecated("Use GCM instead")
    fun encrypt(aesEngine: BufferedBlockCipher, aesKey: ByteArray, aesIV: ByteArray, data: ByteArray, logger: Logger? = null): ByteArray {
        val length = data.size

        val aesIVAndKey: CipherParameters = ParametersWithIV(KeyParameter(aesKey), aesIV)
        aesEngine.reset()
        aesEngine.init(true, aesIVAndKey)

        val minSize = aesEngine.getOutputSize(length)
        val outBuf = ByteArray(minSize)

        var actualLength = aesEngine.processBytes(data, 0, length, outBuf, 0)

        try {
            actualLength += aesEngine.doFinal(outBuf, actualLength)
        }
        catch (e: Exception) {
            logger?.error("Unable to perform AES cipher.", e)
            return ByteArray(0)
        }

        if (outBuf.size == actualLength) {
            return outBuf
        }
        else {
            val result = ByteArray(actualLength)
            System.arraycopy(outBuf, 0, result, 0, result.size)
            return result
        }
    }

    /**
     * **CONVENIENCE METHOD ONLY - DO NOT USE UNLESS YOU HAVE TO**
     * 
     * 
     * Use GCM instead, as it's an authenticated cipher (and "regular" AES is not). This prevents tampering with the blocks of encrypted
     * data.
     * 
     * 
     * AES encrypt from one stream to another.
     * 
     * @param aesIV must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return true if successful
     */
    @Deprecated("User GCM instead")
    fun encryptStream(
        aesEngine: BufferedBlockCipher,
        aesKey: ByteArray,
        aesIV: ByteArray,
        `in`: InputStream,
        out: OutputStream,
        logger: Logger? = null
    ): Boolean {
        val buf = ByteArray(ivSize)
        val outbuf = ByteArray(512)

        val aesIVAndKey: CipherParameters = ParametersWithIV(KeyParameter(aesKey), aesIV)
        aesEngine.reset()
        aesEngine.init(true, aesIVAndKey)

        try {
            var bytesRead: Int
            var bytesProcessed: Int

            while ((`in`.read(buf).also { bytesRead = it }) >= 0) {
                bytesProcessed = aesEngine.processBytes(buf, 0, bytesRead, outbuf, 0)
                out.write(outbuf, 0, bytesProcessed)
            }

            bytesProcessed = aesEngine.doFinal(outbuf, 0)

            out.write(outbuf, 0, bytesProcessed)
            out.flush()
        }
        catch (e: Exception) {
            logger?.error("Unable to perform AES cipher.", e)
            return false
        }

        return true
    }

    /**
     * AES encrypt from one stream to another.
     * 
     * @param logger may be null, if no log output is necessary
     * @param aesIV must be a nonce (unique value) !!
     * 
     * @return true if successful
     */
    fun encryptStream(
        aesEngine: GCMBlockCipher,
        aesKey: ByteArray,
        aesIV: ByteArray,
        `in`: InputStream,
        out: OutputStream,
        logger: Logger? = null
    ): Boolean {
        val buf = ByteArray(ivSize)
        val outbuf = ByteArray(512)

        val aesIVAndKey: CipherParameters = ParametersWithIV(KeyParameter(aesKey), aesIV)
        aesEngine.reset()
        aesEngine.init(true, aesIVAndKey)

        try {
            var bytesRead: Int
            var bytesProcessed: Int

            while ((`in`.read(buf).also { bytesRead = it }) >= 0) {
                bytesProcessed = aesEngine.processBytes(buf, 0, bytesRead, outbuf, 0)
                out.write(outbuf, 0, bytesProcessed)
            }

            bytesProcessed = aesEngine.doFinal(outbuf, 0)

            out.write(outbuf, 0, bytesProcessed)
            out.flush()
        }
        catch (e: Exception) {
            logger?.error("Unable to perform AES cipher.", e)
            return false
        }

        return true
    }

    /**
     * AES decrypt (if the aes IV is included in the data). IV must be a nonce (unique value) !!
     * 
     * @param logger may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    fun decryptWithIV(aesEngine: GCMBlockCipher, aesKey: ByteArray, data: ByteArray, logger: Logger? = null): ByteArray {
        val aesIV = ByteArray(ivSize)
        System.arraycopy(data, 0, aesIV, 0, ivSize)

        val `in` = ByteArray(data.size - ivSize)
        System.arraycopy(data, ivSize, `in`, 0, `in`.size)

        return decrypt(aesEngine, aesKey, aesIV, `in`, logger)
    }

    /**
     * **CONVENIENCE METHOD ONLY - DO NOT USE UNLESS YOU HAVE TO**
     * 
     * 
     * Use GCM instead, as it's an authenticated cipher (and "regular" AES is not). This prevents tampering with the blocks of encrypted
     * data.
     * 
     * 
     * AES decrypt (if the aes IV is included in the data). IV must be a nonce (unique value)
     * 
     * @param logger may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    @Deprecated("Use GCM instead")
    fun decryptWithIV(aesEngine: BufferedBlockCipher, aesKey: ByteArray, data: ByteArray, logger: Logger? = null): ByteArray {
        val aesIV = ByteArray(ivSize)
        System.arraycopy(data, 0, aesIV, 0, ivSize)

        val `in` = ByteArray(data.size - ivSize)
        System.arraycopy(data, ivSize, `in`, 0, `in`.size)

        return decrypt(aesEngine, aesKey, aesIV, `in`, logger)
    }

    /**
     * AES decrypt (if the aes IV is included in the data. IV must be a nonce (unique value)
     * 
     * @param logger may be null, if no log output is necessary
     * 
     * @return true if successful
     */
    fun decryptStreamWithIV(aesEngine: GCMBlockCipher, aesKey: ByteArray, `in`: InputStream, out: OutputStream, logger: Logger? = null): Boolean {
        val aesIV = ByteArray(ivSize)
        try {
            `in`.read(aesIV, 0, ivSize)
        }
        catch (e: Exception) {
            logger?.error("Unable to perform AES cipher.", e)
            return false
        }

        return decryptStream(aesEngine, aesKey, aesIV, `in`, out, logger)
    }

    /**
     * **CONVENIENCE METHOD ONLY - DO NOT USE UNLESS YOU HAVE TO**
     * 
     * 
     * Use GCM instead, as it's an authenticated cipher (and "regular" AES is not). This prevents tampering with the blocks of encrypted
     * data.
     * 
     * 
     * AES decrypt (if the aes IV is included in the data). IV must be a nonce (unique value)
     * 
     * @param logger may be null, if no log output is necessary
     * 
     * @return true if successful
     */
    @Deprecated("Use GCM instead")
    fun decryptStreamWithIV(
        aesEngine: BufferedBlockCipher,
        aesKey: ByteArray,
        `in`: InputStream,
        out: OutputStream,
        logger: Logger? = null
    ): Boolean {
        val aesIV = ByteArray(ivSize)
        try {
            `in`.read(aesIV, 0, ivSize)
        }
        catch (e: Exception) {
            logger?.error("Unable to perform AES cipher.", e)
            return false
        }

        return decryptStream(aesEngine, aesKey, aesIV, `in`, out, logger)
    }

    /**
     * AES decrypt (if we already know the aes IV -- and it's NOT included in the data)
     * 
     * @param aesIV must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    fun decrypt(aesEngine: GCMBlockCipher, aesKey: ByteArray, aesIV: ByteArray, data: ByteArray, logger: Logger? = null): ByteArray {
        val length = data.size

        val aesIVAndKey: CipherParameters = ParametersWithIV(KeyParameter(aesKey), aesIV)
        aesEngine.reset()
        aesEngine.init(false, aesIVAndKey)

        val minSize = aesEngine.getOutputSize(length)
        val outBuf = ByteArray(minSize)

        var actualLength = aesEngine.processBytes(data, 0, length, outBuf, 0)

        try {
            actualLength += aesEngine.doFinal(outBuf, actualLength)
        }
        catch (e: Exception) {
            logger?.debug("Unable to perform AES cipher.", e)
            return ByteArray(0)
        }
        if (outBuf.size == actualLength) {
            return outBuf
        }
        else {
            val result = ByteArray(actualLength)
            System.arraycopy(outBuf, 0, result, 0, result.size)
            return result
        }
    }

    /**
     * **CONVENIENCE METHOD ONLY - DO NOT USE UNLESS YOU HAVE TO**
     * 
     * 
     * Use GCM instead, as it's an authenticated cipher (and "regular" AES is not). This prevents tampering with the blocks of encrypted
     * data.
     * 
     * 
     * AES decrypt (if we already know the aes IV -- and it's NOT included in the data)
     * 
     * @param aesIV  must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return empty byte[] if error
     */
    @Deprecated("Use GCM instead")
    fun decrypt(aesEngine: BufferedBlockCipher, aesKey: ByteArray, aesIV: ByteArray, data: ByteArray, logger: Logger? = null): ByteArray {
        val length = data.size

        val aesIVAndKey: CipherParameters = ParametersWithIV(KeyParameter(aesKey), aesIV)
        aesEngine.reset()
        aesEngine.init(false, aesIVAndKey)

        val minSize = aesEngine.getOutputSize(length)
        val outBuf = ByteArray(minSize)

        var actualLength = aesEngine.processBytes(data, 0, length, outBuf, 0)

        try {
            actualLength += aesEngine.doFinal(outBuf, actualLength)
        }
        catch (e: Exception) {
            logger?.error("Unable to perform AES cipher.", e)
            return ByteArray(0)
        }

        if (outBuf.size == actualLength) {
            return outBuf
        }
        else {
            val result = ByteArray(actualLength)
            System.arraycopy(outBuf, 0, result, 0, result.size)
            return result
        }
    }

    /**
     * AES decrypt from one stream to another.
     * 
     * @param aesIV must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return true if successful
     */
    fun decryptStream(
        aesEngine: GCMBlockCipher,
        aesKey: ByteArray,
        aesIV: ByteArray,
        `in`: InputStream,
        out: OutputStream,
        logger: Logger? = null
    ): Boolean {
        val buf = ByteArray(ivSize)
        val outbuf = ByteArray(512)

        val aesIVAndKey: CipherParameters = ParametersWithIV(KeyParameter(aesKey), aesIV)
        aesEngine.reset()
        aesEngine.init(false, aesIVAndKey)

        try {
            var bytesRead: Int
            var bytesProcessed: Int

            while ((`in`.read(buf).also { bytesRead = it }) >= 0) {
                bytesProcessed = aesEngine.processBytes(buf, 0, bytesRead, outbuf, 0)
                out.write(outbuf, 0, bytesProcessed)
            }

            bytesProcessed = aesEngine.doFinal(outbuf, 0)

            out.write(outbuf, 0, bytesProcessed)
            out.flush()
        }
        catch (e: Exception) {
            logger?.error("Unable to perform AES cipher.", e)
            return false
        }

        return true
    }

    /**
     * **CONVENIENCE METHOD ONLY - DO NOT USE UNLESS YOU HAVE TO**
     * 
     * 
     * Use GCM instead, as it's an authenticated cipher (and "regular" AES is not). This prevents tampering with the blocks of encrypted
     * data.
     * 
     * 
     * AES decrypt from one stream to another.
     * 
     * @param aesIV must be a nonce (unique value) !!
     * @param logger may be null, if no log output is necessary
     * 
     * @return true if successful
     */
    @Deprecated("Use GCM instead")
    fun decryptStream(
        aesEngine: BufferedBlockCipher,
        aesKey: ByteArray,
        aesIV: ByteArray,
        `in`: InputStream,
        out: OutputStream,
        logger: Logger? = null
    ): Boolean {
        val buf = ByteArray(ivSize)
        val outbuf = ByteArray(512)

        val aesIVAndKey: CipherParameters = ParametersWithIV(KeyParameter(aesKey), aesIV)
        aesEngine.reset()
        aesEngine.init(false, aesIVAndKey)

        try {
            var bytesRead: Int
            var bytesProcessed: Int

            while ((`in`.read(buf).also { bytesRead = it }) >= 0) {
                bytesProcessed = aesEngine.processBytes(buf, 0, bytesRead, outbuf, 0)
                out.write(outbuf, 0, bytesProcessed)
            }

            bytesProcessed = aesEngine.doFinal(outbuf, 0)

            out.write(outbuf, 0, bytesProcessed)
            out.flush()
        }
        catch (e: Exception) {
            logger?.error("Unable to perform AES cipher.", e)
            return false
        }

        return true
    }
}
