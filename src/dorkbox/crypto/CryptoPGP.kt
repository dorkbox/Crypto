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

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.*
import java.io.*
import java.nio.charset.StandardCharsets
import java.security.NoSuchProviderException
import java.security.SecureRandom
import java.util.*
import java.util.regex.*

/**
 * PGP crypto related methods
 */
class CryptoPGP {

    private constructor()

    /**
     * Get the first decryption key from the given keyring.
     */
    fun getDecryptionKey(keyRing: PGPSecretKeyRing?): PGPSecretKey? {
        if (keyRing == null) {
            return null
        }

        // iterate over the keys on the ring, look for one which is suitable for encryption.
        val keys: MutableIterator<*> = keyRing.secretKeys
        var key: PGPSecretKey
        while (keys.hasNext()) {
            key = keys.next() as PGPSecretKey
            if (key.isMasterKey) {
                return key
            }
        }

        return null
    }


    /**
     * Encrypt plaintext message using public key from publickeyFile.
     * 
     * @param message
     * the message
     * 
     * @return the string
     */
    @Throws(PGPException::class, IOException::class, NoSuchProviderException::class)
    private fun encrypt(publicKeyInputStream: InputStream, message: String): String? {
        // find the PGP key in the file
        val publicKey = findPublicGPGKey(publicKeyInputStream)

        if (publicKey == null) {
            System.err.println("Did not find public GPG key")
            return null
        }


        // Encode the string into bytes using utf-8
        val utf8Bytes = message.toByteArray(StandardCharsets.UTF_8)

        val compressedOutput = ByteArrayOutputStream()

        // compress bytes with zip
        val literalDataGenerator = PGPLiteralDataGenerator()

        // the reason why we compress here is GPG not being able to decrypt our message input but if we do not compress.
        // I guess pkzip compression also encodes only to GPG-friendly characters.
        val compressedDataGenerator = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
        try {
            val literalDataOutput = literalDataGenerator.open(
                compressedOutput, PGPLiteralData.BINARY, "_CONSOLE", utf8Bytes.size.toLong(), Date()
            )
            // update bytes in the stream
            literalDataOutput.write(utf8Bytes)
        }
        catch (e: IOException) {
            // catch but close the streams in finally
            throw e
        }
        finally {
            compressedDataGenerator.close()
            close(compressedOutput)
        }

        val random = SecureRandom()

        // now we have zip-compressed bytes
        val compressedBytes = compressedOutput.toByteArray()

        val bcPGPDataEncryptorBuilder =
            BcPGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(true).setSecureRandom(random)

        val encryptedDataGenerator = PGPEncryptedDataGenerator(bcPGPDataEncryptorBuilder)

        // use public key to encrypt data
        val encKeyGen = BcPublicKeyKeyEncryptionMethodGenerator(publicKey).setSecureRandom(random)

        encryptedDataGenerator.addMethod(encKeyGen)

        // literalDataOutput --> compressedOutput --> ArmoredOutputStream --> ByteArrayOutputStream
        val byteArrayOutputStream = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(byteArrayOutputStream)
        var encryptedOutput: OutputStream? = null
        try {
            encryptedOutput = encryptedDataGenerator.open(armoredOut, compressedBytes.size.toLong())
            encryptedOutput.write(compressedBytes)
        }
        catch (e: IOException) {
            throw e
        }
        catch (e: PGPException) {
            throw e
        }
        finally {
            close(encryptedOutput)
            close(armoredOut)
        }
        val encrypted = String(byteArrayOutputStream.toByteArray())

        System.err.println("Message: " + message)
        System.err.println("Encrypted: " + encrypted)

        return encrypted
    }

    companion object {
        /**
         * Gets the version number.
         */
        const val version = Crypto.version

        private val digestCalculatorProvider = BcPGPDigestCalculatorProvider()
        private val fingerprintCalculator = BcKeyFingerprintCalculator()


        //    https://github.com/weiliatgithub/bouncycastle-gpg-exampleC
        //    https://gist.github.com/turingbirds/3df43f1920a98010667a
        //    http://sloanseaman.com/wordpress/2012/05/13/revisited-pgp-encryptiondecryption-in-java/
        //    http://bouncycastle-pgp-cookbook.blogspot.de/
        /**
         * Sign a message using our private PGP key file, this matches gpg -ab "hello.txt"
         * 
         * @param privateKeyInputStream
         * this is an armored key file, not a binary stream
         * @param userId
         * this is the userID to get out of the private key
         * @param password
         * this is the password to unlock the private key
         * @param messageAsUtf8Bytes
         * this is the message, in bytes, to sign
         */
        @Throws(PGPException::class)
        fun signGpgCompatible(
            privateKeyInputStream: InputStream,
            userId: String,
            password: CharArray,
            messageAsUtf8Bytes: ByteArray
        ): ByteArray {
            // the signature type (in gpg terms), is "sigclass". gpg is BINARY_DOC (0x00)

            return sign(
                privateKeyInputStream,
                userId,
                password,
                ByteArrayInputStream(messageAsUtf8Bytes),
                PGPSignature.BINARY_DOCUMENT,
                false,
                true,
                false,
                false,
                false
            )
        }

        /**
         * Sign a message using our private PGP key file, this matches gpg -ab "hello.txt"
         * 
         * @param privateKeyInputStream
         * this is an armored key file, not a binary stream
         * @param userId
         * this is the userID to get out of the private key
         * @param password
         * this is the password to unlock the private key
         * @param message
         * this is the message to sign
         */
        @Throws(PGPException::class)
        fun signGpgCompatible(privateKeyInputStream: InputStream, userId: String, password: CharArray, message: InputStream): ByteArray {
            // the signature type (in gpg terms), is "sigclass". gpg is BINARY_DOC (0x00)

            return sign(
                privateKeyInputStream, userId, password, message, PGPSignature.BINARY_DOCUMENT, false, true, false, false, false
            )
        }

        /**
         * Sign a message using our private PGP key file, this matches gpg -ab "hello.txt". This will save the signature of the passed-in
         * file to file name + .asc
         * 
         * @param privateKeyInputStream
         * this is an armored key file, not a binary stream
         * @param userId
         * this is the userID to get out of the private key
         * @param password
         * this is the password to unlock the private key
         * @param file
         * this is the file to sign
         */
        @Throws(PGPException::class)
        fun signGpgCompatible(privateKeyInputStream: InputStream, userId: String, password: CharArray, file: File) {
            // the signature type (in gpg terms), is "sigclass". gpg is BINARY_DOC (0x00)

            val sign: ByteArray = sign(
                privateKeyInputStream, userId, password, file, PGPSignature.BINARY_DOCUMENT, false, true, false, false, false
            )

            var fileOutputStream1: FileOutputStream? = null
            try {
                fileOutputStream1 = FileOutputStream(File(file.absolutePath + ".asc"))
                fileOutputStream1.write(sign)
                fileOutputStream1.flush()
            }
            catch (e: FileNotFoundException) {
                throw PGPException("Unable to save signature to file " + file.absolutePath + ".asc", e)
            }
            catch (e: IOException) {
                throw PGPException("Unable to save signature to file " + file.absolutePath + ".asc", e)
            }
            finally {
                close(fileOutputStream1)
            }
        }

        /**
         * Sign a message using our private PGP key file, with a variety of options
         */
        @Throws(PGPException::class)
        fun sign(
            privateKeyInputStream: InputStream,
            userId: String,
            password: CharArray,
            message: InputStream,
            signatureType: Int,
            compressSignature: Boolean,
            asciiArmoredOutput: Boolean,
            includeDataInSignature: Boolean,
            generateUserIdSubPacket: Boolean,
            generateOnePassVersion: Boolean
        ): ByteArray {
            val secretKeys = getSecretKeys(privateKeyInputStream, userId)
            val signature = createSignature(secretKeys, password, signatureType, generateUserIdSubPacket)

            val byteArrayOutputStream = ByteArrayOutputStream()
            var outputStream: OutputStream = byteArrayOutputStream
            if (asciiArmoredOutput) {
                outputStream = ArmoredOutputStream(byteArrayOutputStream)
            }

            var compressedDataGenerator: PGPCompressedDataGenerator? = null
            val bcOutputStream: BCPGOutputStream?

            if (compressSignature) {
                compressedDataGenerator = PGPCompressedDataGenerator(PGPCompressedData.ZLIB)
                try {
                    bcOutputStream = BCPGOutputStream(compressedDataGenerator.open(outputStream))
                }
                catch (e: IOException) {
                    throw PGPException("Unable to open compression stream in the signature", e)
                }
            }
            else {
                bcOutputStream = BCPGOutputStream(outputStream)
            }

            if (generateOnePassVersion) {
                try {
                    signature.generateOnePassVersion(false).encode(bcOutputStream)
                }
                catch (e: IOException) {
                    throw PGPException("Unable to generate OnePass signature header", e)
                }
            }

            var literalDataGenerator: PGPLiteralDataGenerator? = null
            var literalDataOutput: OutputStream? = null

            if (includeDataInSignature) {
                literalDataGenerator = PGPLiteralDataGenerator()
                try {
                    literalDataOutput = literalDataGenerator.open(
                        bcOutputStream, PGPLiteralData.BINARY, "_CONSOLE", message.available().toLong(), Date()
                    )
                }
                catch (e1: IOException) {
                    throw PGPException("Unable to generate Literal Data signature header", e1)
                }
            }

            try {
                val buffer = ByteArray(4096)
                var read: Int

                // update bytes in the streams
                if (literalDataOutput != null) {
                    while ((message.read(buffer).also { read = it }) > 0) {
                        literalDataOutput.write(buffer, 0, read)
                        signature.update(buffer, 0, read)
                    }
                    literalDataOutput.flush()
                }
                else {
                    while ((message.read(buffer).also { read = it }) > 0) {
                        signature.update(buffer, 0, read)
                    }
                }

                // close generators and update signature
                if (literalDataGenerator != null) {
                    literalDataGenerator.close()
                }

                signature.generate().encode(bcOutputStream)


                if (compressedDataGenerator != null) {
                    compressedDataGenerator.close()
                }
            }
            catch (e: Exception) {
                e.printStackTrace()
            }
            finally {
                close(bcOutputStream)
                close(outputStream)
                close(literalDataOutput)
            }

            return byteArrayOutputStream.toByteArray()
        }

        /**
         * Sign a message using our private PGP key file, with a variety of options
         */
        @Throws(PGPException::class)
        fun sign(
            privateKeyInputStream: InputStream,
            userId: String,
            password: CharArray,
            fileMessage: File,
            signatureType: Int,
            compressSignature: Boolean,
            asciiArmoredOutput: Boolean,
            includeDataInSignature: Boolean,
            generateUserIdSubPacket: Boolean,
            generateOnePassVersion: Boolean
        ): ByteArray {
            val secretKeys = getSecretKeys(privateKeyInputStream, userId)
            val signature = createSignature(secretKeys, password, signatureType, generateUserIdSubPacket)

            val byteArrayOutputStream = ByteArrayOutputStream()
            var outputStream: OutputStream = byteArrayOutputStream
            if (asciiArmoredOutput) {
                outputStream = ArmoredOutputStream(byteArrayOutputStream)
            }

            var compressedDataGenerator: PGPCompressedDataGenerator? = null
            val bcOutputStream: BCPGOutputStream?

            if (compressSignature) {
                compressedDataGenerator = PGPCompressedDataGenerator(PGPCompressedData.ZLIB)
                try {
                    bcOutputStream = BCPGOutputStream(compressedDataGenerator.open(outputStream))
                }
                catch (e: IOException) {
                    throw PGPException("Unable to open compression stream in the signature", e)
                }
            }
            else {
                bcOutputStream = BCPGOutputStream(outputStream)
            }

            if (generateOnePassVersion) {
                try {
                    signature.generateOnePassVersion(false).encode(bcOutputStream)
                }
                catch (e: IOException) {
                    throw PGPException("Unable to generate OnePass signature header", e)
                }
            }

            var literalDataGenerator: PGPLiteralDataGenerator? = null
            var literalDataOutput: OutputStream? = null

            if (includeDataInSignature) {
                literalDataGenerator = PGPLiteralDataGenerator()
                try {
                    literalDataOutput = literalDataGenerator.open(
                        bcOutputStream, PGPLiteralData.BINARY, fileMessage
                    )
                }
                catch (e1: IOException) {
                    throw PGPException("Unable to generate Literal Data signature header", e1)
                }
            }

            try {
                val fileInputStream = FileInputStream(fileMessage)

                val buffer = ByteArray(4096)
                var read: Int

                // update bytes in the streams
                if (literalDataOutput != null) {
                    while ((fileInputStream.read(buffer).also { read = it }) > 0) {
                        literalDataOutput.write(buffer, 0, read)
                        signature.update(buffer, 0, read)
                    }
                    literalDataOutput.flush()
                }
                else {
                    while ((fileInputStream.read(buffer).also { read = it }) > 0) {
                        signature.update(buffer, 0, read)
                    }
                }

                // close generators and update signature
                if (literalDataGenerator != null) {
                    literalDataGenerator.close()
                }

                signature.generate().encode(bcOutputStream)


                if (compressedDataGenerator != null) {
                    compressedDataGenerator.close()
                }
            }
            catch (e: Exception) {
                e.printStackTrace()
            }
            finally {
                close(bcOutputStream)
                close(outputStream)
                close(literalDataOutput)
            }

            return byteArrayOutputStream.toByteArray()
        }


        /**
         * Find private gpg key in InputStream, also closes the input stream
         * 
         * @param inputStream
         * the inputStream that contains the private (secret) key
         * @param userId
         * the user id
         * 
         * @return the PGP secret key
         */
        @Throws(PGPException::class)
        fun getSecretKeys(inputStream: InputStream, userId: String): MutableList<PGPSecretKey> {
            // iterate over every private key in the key ring
            var secretKeyRings: PGPSecretKeyRingCollection?
            try {
                secretKeyRings = PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(inputStream), fingerprintCalculator)
            }
            catch (e: IOException) {
                throw PGPException("No private key found in stream!", e)
            }
            finally {
                close(inputStream)
            }

            // look for the key ring that is used to authenticate our reporting facilities
            val secretKeys = secretKeyRings.getKeyRings(userId)
            val pgpSecretKeys: MutableList<PGPSecretKey> = mutableListOf()

            // iterate over every private key in the ring
            while (secretKeys.hasNext()) {
                val secretKeyRing = secretKeys.next()
                val tmpKey = secretKeyRing.secretKey

                if (tmpKey != null) {
                    pgpSecretKeys.add(tmpKey)
                }
            }

            return pgpSecretKeys
        }

        /**
         * Creates the signature that will be used to PGP sign data
         * 
         * @param secretKeys
         * these are the secret keys
         * @param password
         * this is the password to unlock the secret key
         * 
         * @return the signature used to sign data
         * 
         * @throws PGPException
         */
        @Throws(PGPException::class)
        private fun createSignature(
            secretKeys: MutableList<PGPSecretKey>,
            password: CharArray = CharArray(0),
            signatureType: Int,
            generateUserIdSubPacket: Boolean
        ): PGPSignatureGenerator {
            var password = password
            var secretKey: PGPSecretKey? = null

            for (i in secretKeys.indices) {
                secretKey = secretKeys[i]

                // we ONLY want the signing master key
                if (!secretKey.isSigningKey() || !secretKey.isMasterKey) {
                    secretKey = null
                }
            }

            if (secretKey == null) {
                throw PGPException("Secret key is not the signing master key")
            }

            //            System.err.println("Signing key = " + tmpKey.isSigningKey() +", Master key = " + tmpKey.isMasterKey() + ", UserId = " +
//                               userId );

            val build = BcPBESecretKeyDecryptorBuilder(digestCalculatorProvider).build(password)

            val random = SecureRandom()
            val bcPGPContentSignerBuilder = BcPGPContentSignerBuilder(
                secretKey.publicKey.algorithm, PGPUtil.SHA1
            ).setSecureRandom(random)

            val signature = PGPSignatureGenerator(bcPGPContentSignerBuilder)
            signature.init(signatureType, secretKey.extractPrivateKey(build))

            val userIds: MutableIterator<*> = secretKey.publicKey.getUserIDs()

            // use the first userId that matches
            if (userIds.hasNext()) {
                if (generateUserIdSubPacket) {
                    val subpacketGenerator = PGPSignatureSubpacketGenerator()
                    subpacketGenerator.addSignerUserID(false, userIds.next() as String?)
                    signature.setHashedSubpackets(subpacketGenerator.generate())
                }
                else {
                    signature.setHashedSubpackets(null)
                }

                return signature
            }
            else {
                throw PGPException("Did not find specified userId")
            }
        }



        /**
         * Decode a PGP public key block and return the keyring it represents.
         */
        @Throws(IOException::class)
        fun getKeyring(keyBlockStream: InputStream): PGPPublicKeyRing? {
            val keyfp = BcKeyFingerprintCalculator()

            // PGPUtil.getDecoderStream() will detect ASCII-armor automatically and decode it,
            // the PGPObject factory then knows how to read all the data in the encoded stream
            val factory = PGPObjectFactory(PGPUtil.getDecoderStream(keyBlockStream), keyfp)

            // these files should really just have one object in them, and that object should be a PGPPublicKeyRing.
            val o = factory.nextObject()
            if (o is PGPPublicKeyRing) {
                return o
            }

            return null
        }

        /**
         * Get the first encryption key from the given keyring.
         */
        fun getEncryptionKey(keyRing: PGPPublicKeyRing): PGPPublicKey? {
            // iterate over the keys on the ring, look for one which is suitable for encryption.
            val keys: MutableIterator<*> = keyRing.publicKeys
            var key: PGPPublicKey
            while (keys.hasNext()) {
                key = keys.next() as PGPPublicKey
                if (key.isEncryptionKey()) {
                    return key
                }
            }

            return null
        }

        /**
         * Find public gpg key in InputStream.
         * 
         * @param inputStream
         * the input stream
         * 
         * @return the PGP public key
         */
        @Throws(IOException::class, PGPException::class)
        private fun findPublicGPGKey(inputStream: InputStream): PGPPublicKey? {
            // get all key rings in the input stream

            val publicKeyRingCollection = PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(inputStream), fingerprintCalculator)

            System.err.println("key ring size: " + publicKeyRingCollection.size())

            val keyRingIter = publicKeyRingCollection.keyRings

            // iterate over keyrings
            while (keyRingIter.hasNext()) {
                val keyRing = keyRingIter.next()
                val keyIter = keyRing.publicKeys
                // iterate over public keys in the key ring
                while (keyIter.hasNext()) {
                    val tmpKey = keyIter.next()

                    if (tmpKey == null) {
                        break
                    }

                    val userIDs = tmpKey.getUserIDs()
                    val strings = ArrayList<String?>()
                    while (userIDs.hasNext()) {
                        val next = userIDs.next()
                        strings.add(next)
                    }

                    System.err.println(
                        "Encryption key = " + tmpKey.isEncryptionKey() + ", Master key = " + tmpKey.isMasterKey + ", UserId = " + strings
                    )

                    // we need a master encryption key
                    if (tmpKey.isEncryptionKey() && tmpKey.isMasterKey) {
                        return tmpKey
                    }
                }
            }

            return null
        }



        @Throws(Exception::class)
        private fun verify(publicKeyInputStream: InputStream, signature: ByteArray) {
            val publicKey = findPublicGPGKey(publicKeyInputStream)

            val text = String(signature)

            val regex = Pattern.compile(
                "-----BEGIN PGP SIGNED MESSAGE-----\\r?\\n.*?\\r?\\n\\r?\\n(.*)\\r?\\n(-----BEGIN PGP SIGNATURE-----\\r?\\n.*-----END PGP SIGNATURE-----)",
                Pattern.CANON_EQ or Pattern.DOTALL
            )
            val regexMatcher = regex.matcher(text)
            if (regexMatcher.find()) {
                val dataText = regexMatcher.group(1)
                val signText = regexMatcher.group(2)

                val dataIn = ByteArrayInputStream(dataText.toByteArray(charset("UTF8")))
                val signIn = ByteArrayInputStream(signText.toByteArray(charset("UTF8")))


                val signIn2 = PGPUtil.getDecoderStream(signIn)

                var pgpFact = PGPObjectFactory(signIn2, BcKeyFingerprintCalculator())
                var p3: PGPSignatureList? = null

                val o = pgpFact.nextObject()

                if (o is PGPCompressedData) {
                    pgpFact = PGPObjectFactory(o.getDataStream(), BcKeyFingerprintCalculator())

                    p3 = pgpFact.nextObject() as PGPSignatureList?
                }
                else {
                    p3 = o as PGPSignatureList
                }


                //            PGPSignature sig = p3.get(0);
//            PGPPublicKey key = KeyRing.getPublicKeyByID(sig.getKeyID());
//
//            if (key == null)
//                throw new Exception("Cannot find key 0x" + Integer.toHexString((int) sig.getKeyID()).toUpperCase() + " in the pubring");
//
//            sig.initVerify(key, "BC");
//
//            while ((ch = dataIn.read()) >= 0) {
//                sig.update((byte) ch); //TODO migliorabile con byte[]
//            }
//
//            if (sig.verify())
//                return new PrintablePGPPublicKey(key).toString();
//            else
//                return null;

//            return verifyFile(dataIn, signIn);
            }
        }


        @Throws(Exception::class)
        @JvmStatic
        fun main(args: Array<String>) {
            val privateKeyInputStream: InputStream = FileInputStream(File("/home/user/dorkbox/sonatype_private.key"))

            val textBytes = "hello".toByteArray(StandardCharsets.UTF_8)

            val bytes: ByteArray = signGpgCompatible(privateKeyInputStream, "Dorkbox <sonatype@dorkbox.com>", CharArray(0), textBytes)


            //        String s = new String(hello);
//        String s1 = s.replaceAll("\n", "\r\n");
//        byte[] bytes = s1.getBytes(OS.UTF_8);

//
//        String signed = new String(bytes);
//
//        System.err.println("Message: " + new String(messageAsUtf8Bytes));
//        System.err.println("Signature: " + signed);
//
//        return bytes;

//        String s2 = new String(bytes);


//        InputStream publicKeyInputStream = new FileInputStream(new File("/home/user/dorkbox/sonatype_public.key"));
//        cryptoPGP.verify(publicKeyInputStream, hello);
            val fileOutputStream = FileOutputStream(File("/home/user/dorkbox/hello2.txt"))
            fileOutputStream.write(textBytes)
            fileOutputStream.flush()
            close(fileOutputStream)


            val fileOutputStream1 = FileOutputStream(File("/home/user/dorkbox/hello2.txt.asc"))
            fileOutputStream1.write(bytes)
            fileOutputStream1.flush()
            close(fileOutputStream1)
        }

        private fun close(closeable: Closeable?) {
            if (closeable != null) {
                try {
                    closeable.close()
                }
                catch (e: IOException) {
                    System.err.println("Error closing : " + closeable)
                    e.printStackTrace()
                }
            }
        }
    }
}
