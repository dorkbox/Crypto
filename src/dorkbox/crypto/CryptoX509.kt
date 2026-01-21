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

import dorkbox.crypto.signers.BcECDSAContentSignerBuilder
import dorkbox.crypto.signers.BcECDSAContentVerifierProviderBuilder
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.cms.*
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.RSAPublicKey
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.*
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.cert.X509CertificateHolder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator
import org.bouncycastle.crypto.params.*
import org.bouncycastle.jcajce.provider.asymmetric.dsa.BCDSAPublicKey
import org.bouncycastle.jcajce.provider.asymmetric.dsa.DSAUtil
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
import org.bouncycastle.jcajce.provider.asymmetric.rsa.BCRSAPublicKey
import org.bouncycastle.jcajce.provider.asymmetric.rsa.RSAUtil
import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory
import org.bouncycastle.jce.PrincipalUtil
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.provider.JCEECPublicKey
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.bc.*
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.io.*
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateEncodingException
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.spec.InvalidKeySpecException
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.*

object CryptoX509 {
    /**
     * Gets the version number.
     */
    const val version = Crypto.version


    private val logger: Logger = LoggerFactory.getLogger(CryptoX509::class.java)

    fun addProvider() {
        // make sure we only add it once (in case it's added elsewhere...)
        val provider = Security.getProvider("BC")
        if (provider == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /**
     * Creates a NEW signature block that contains the pkcs7 (minus content, which is the .SF file)
     * signature of the .SF file.
     * 
     * It contains the hash of the data, and the verification signature.
     */
    fun createSignature(signatureSourceData: ByteArray, x509CertificateHolder: X509CertificateHolder, privateKey: AsymmetricKeyParameter): ByteArray? {
        try {
            val content: CMSTypedData = CMSProcessableByteArray(signatureSourceData)

            val contentTypeOID = ASN1ObjectIdentifier(content.contentType.id)
            val digestAlgs = ASN1EncodableVector()
            val signerInfos = ASN1EncodableVector()

            val sigAlgId = x509CertificateHolder.signatureAlgorithm
            val digAlgId = DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId)

            // use the bouncy-castle lightweight API to generate a hash of the signature source data (usually the signature file bytes)
            val contentSignerBuilder: BcContentSignerBuilder?
            val digEncryptionAlgorithm: AlgorithmIdentifier?


            if (privateKey is ECPrivateKeyParameters) {
                contentSignerBuilder = BcECDSAContentSignerBuilder(sigAlgId, digAlgId)
                digEncryptionAlgorithm = AlgorithmIdentifier(DSAUtil.dsaOids[0], null) // 1.2.840.10040.4.1  // DSA hashID
            }
            else if (privateKey is DSAPrivateKeyParameters) {
                contentSignerBuilder = BcDSAContentSignerBuilder(sigAlgId, digAlgId)
                digEncryptionAlgorithm = AlgorithmIdentifier(DSAUtil.dsaOids[0], null) // 1.2.840.10040.4.1  // DSA hashID
            }
            else if (privateKey is RSAPrivateCrtKeyParameters) {
                contentSignerBuilder = BcRSAContentSignerBuilder(sigAlgId, digAlgId)
                digEncryptionAlgorithm = AlgorithmIdentifier(RSAUtil.rsaOids[0], null) // 1.2.840.113549.1.1.1 // RSA hashID
            }
            else {
                throw RuntimeException("Invalid signature type. Only ECDSA, DSA, RSA supported.")
            }

            val hashSigner = contentSignerBuilder.build(privateKey)
            val outputStream = hashSigner.outputStream
            outputStream.write(signatureSourceData, 0, signatureSourceData.size)
            outputStream.flush()
            val sigBytes = hashSigner.signature


            val sigId = SignerIdentifier(IssuerAndSerialNumber(x509CertificateHolder.toASN1Structure()))

            val inf = SignerInfo(sigId, digAlgId, null, digEncryptionAlgorithm, DEROctetString(sigBytes), null as ASN1Set?)

            digestAlgs.add(inf.digestAlgorithm)
            signerInfos.add(inf)


            val certs = ASN1EncodableVector()
            certs.add(x509CertificateHolder.toASN1Structure())


            val encInfo = ContentInfo(contentTypeOID, null)
            val sd = SignedData(
                DERSet(digestAlgs), encInfo, BERSet(certs), null, DERSet(signerInfos)
            )


            val contentInfo = ContentInfo(CMSObjectIdentifiers.signedData, sd)
            val cmsSignedData2 = CMSSignedData(content, contentInfo)

            return cmsSignedData2.encoded
        }
        catch (t: Throwable) {
            logger.error("Error signing data.", t)
            return null
        }
    }

    /**
     * Load a key and certificate from a Java KeyStore, and convert the key to a bouncy-castle key.
     * 
     * Code is present but commented out, as it was a PITA to figure it out, as documentation is lacking....
     */
    fun loadKeystore(keystoreLocation: String?, alias: String?, passwd: CharArray?, keypasswd: CharArray?) {
//            FileInputStream fileIn = new FileInputStream(keystoreLocation);
//          KeyStore keyStore = KeyStore.getInstance("JKS");
//          keyStore.load(fileIn, passwd);
//          java.security.cert.Certificate[] chain = keyStore.getCertificateChain(alias);
//          X509Certificate certChain[] = new X509Certificate[chain.length];
//
//          CertificateFactory cf = CertificateFactory.getInstance("X.509");
//          for (int count = 0; count < chain.length; count++) {
//              ByteArrayInputStream certIn = new ByteArrayInputStream(chain[0].getEncoded());
//              X509Certificate cert = (X509Certificate) cf.generateCertificate(certIn);
//              certChain[count] = cert;
//          }
//
//          Key key = keyStore.getKey(alias, keypasswd);
//          KeyFactory keyFactory = KeyFactory.getInstance(key.getAlgorithm());
//          KeySpec keySpec;
//          if (key instanceof DSAPrivateKey) {
//              keySpec = keyFactory.getKeySpec(key, DSAPrivateKeySpec.class);
//          } else {
//              //keySpec = keyFactory.getKeySpec(key, RSAPrivateKeySpec.class);
//              throw new RuntimeException("Only able to support DSA algorithm!");
//          }
//
//          DSAPrivateKey privateKey = (DSAPrivateKey) keyFactory.generatePrivate(keySpec);

        // convert private key to bouncycastle specific
//          DSAParams params = privateKey.getParams();
//          DSAPrivateKeyParameters wimpyPrivKey = new DSAPrivateKeyParameters(privateKey.getX(), new DSAParameters(params.getP(), params.getQ(), params.getG()));
//          X509CertificateHolder x509CertificateHolder = new X509CertificateHolder(certChain[0].getEncoded());
//

//            fileIn.close(); // close JKS
    }

    object Util {
        /**
         * @return true if saving the x509 certificate to a PEM format file was successful
         */
        fun convertToPemFile(x509cert: X509Certificate, fileName: String): Boolean {
            var failed = false
            var output: Writer? = null

            try {
                val lineSeparator = "\r\n"

                val cert_begin = "-----BEGIN CERTIFICATE-----"
                val cert_end = "-----END CERTIFICATE-----"

                val derCert = Base64.getMimeEncoder().encode(x509cert.encoded)
                val encodeToChar = CharArray(derCert.size)

                for (i in derCert.indices) {
                    encodeToChar[i] = Char(derCert[i].toUShort())
                }


                val newLineCount = encodeToChar.size / 64

                val length = encodeToChar.size

                output = BufferedWriter(
                    FileWriter(fileName, false), cert_begin.length + cert_end.length + length + newLineCount + 3
                )

                output.write(cert_begin)
                output.write(lineSeparator)

                var copyCount = 64
                var i = 0
                while (i < length) {
                    if (i + 64 > length) {
                        copyCount = length - i
                    }

                    output.write(encodeToChar, i, copyCount)
                    output.write(lineSeparator)
                    i += 64
                }
                output.write(cert_end)
                output.write(lineSeparator)
            }
            catch (e: Exception) {
                logger.error("Error during conversion.", e)
                failed = true
            }
            finally {
                if (output != null) {
                    try {
                        output.close()
                    }
                    catch (e: IOException) {
                        logger.error("Error closing resource.", e)
                    }
                }
            }

            return !failed
        }

        @Throws(CertificateEncodingException::class)
        fun convertToPem(x509cert: X509Certificate): String {
            val lineSeparator = "\r\n"

            val cert_begin = "-----BEGIN CERTIFICATE-----"
            val cert_end = "-----END CERTIFICATE-----"

            val derCert = Base64.getMimeEncoder().encode(x509cert.encoded)
            val encodeToChar = CharArray(derCert.size)

            for (i in derCert.indices) {
                encodeToChar[i] = Char(derCert[i].toUShort())
            }

            val newLineCount = encodeToChar.size / 64

            val length = encodeToChar.size
            var lastIndex = 0
            val sb = StringBuilder(cert_begin.length + cert_end.length + length + newLineCount + 2)

            sb.append(cert_begin)
            sb.append(lineSeparator)
            var i = 64
            while (i < length) {
                sb.append(encodeToChar, lastIndex, i)
                sb.append(lineSeparator)
                lastIndex = i
                i += 64
            }
            sb.append(cert_end)

            return sb.toString()
        }

        fun getDigestNameFromCert(x509CertificateHolder: X509CertificateHolder): String? {
            return getDigestNameFromSigAlgId(x509CertificateHolder.signatureAlgorithm.algorithm)
        }

        fun getDigestNameFromSigAlgId(algorithm: ASN1ObjectIdentifier): String? {
            var digest: String? = null
            try {
                // have to use reflection in order to access the DIGEST method used by the key.
                val defaultCMSSignatureAlgorithmNameGenerator = DefaultCMSSignatureAlgorithmNameGenerator()
                val declaredMethod = DefaultCMSSignatureAlgorithmNameGenerator::class.java.getDeclaredMethod(
                    "getDigestAlgName", ASN1ObjectIdentifier::class.java
                )
                declaredMethod.setAccessible(true)
                digest = declaredMethod.invoke(defaultCMSSignatureAlgorithmNameGenerator, algorithm) as String?
            }
            catch (t: Throwable) {
                throw RuntimeException("Weird error using reflection to get the digest name: " + algorithm.id + t.message)
            }

            if (algorithm.id == digest) {
                throw RuntimeException("Unable to get digest name from algorithm ID: " + algorithm.id)
            }

            return digest
        }


        //        @SuppressWarnings("rawtypes")
        //        public static void verify(JarFile jf, X509Certificate[] trustedCaCerts) throws IOException, CertificateException {
        //            Vector<JarEntry> entriesVec = new Vector<JarEntry>();
        //
        //            // Ensure there is a manifest file
        //            Manifest man = jf.getManifest();
        //            if (man == null) {
        //                throw new SecurityException("The JAR is not signed");
        //            }
        //
        //            // Ensure all the entries' signatures verify correctly
        //            byte[] buffer = new byte[8192];
        //            Enumeration entries = jf.entries();
        //
        //            while (entries.hasMoreElements()) {
        //                JarEntry je = (JarEntry) entries.nextElement();
        //                entriesVec.addElement(je);
        //                InputStream is = jf.getInputStream(je);
        //                @SuppressWarnings("unused")
        //                int n;
        //                while ((n = is.read(buffer, 0, buffer.length)) != -1) {
        //                    // we just read. this will throw a SecurityException
        //                    // if  a signature/digest check fails.
        //                }
        //                is.close();
        //            }
        //            jf.close();
        //
        //            // Get the list of signer certificates
        //            Enumeration e = entriesVec.elements();
        //            while (e.hasMoreElements()) {
        //                JarEntry je = (JarEntry) e.nextElement();
        //
        //                if (je.isDirectory()) {
        //                    continue;
        //                }
        //                // Every file must be signed - except
        //                // files in META-INF
        //                Certificate[] certs = je.getCertificates();
        //                if (certs == null || certs.length == 0) {
        //                    if (!je.getName().startsWith("META-INF")) {
        //                        throw new SecurityException("The JCE framework has unsigned class files.");
        //                    }
        //                } else {
        //                    // Check whether the file
        //                    // is signed as expected.
        //                    // The framework may be signed by
        //                    // multiple signers. At least one of
        //                    // the signers must be a trusted signer.
        //
        //                    // First, determine the roots of the certificate chains
        //                    X509Certificate[] chainRoots = getChainRoots(certs);
        //                    boolean signedAsExpected = false;
        //
        //                    for (int i = 0; i < chainRoots.length; i++) {
        //                        if (isTrusted(chainRoots[i], trustedCaCerts)) {
        //                            signedAsExpected = true;
        //                            break;
        //                        }
        //                    }
        //
        //                    if (!signedAsExpected) {
        //                        throw new SecurityException("The JAR is not signed by a trusted signer");
        //                    }
        //                }
        //            }
        //        }
        fun isTrusted(cert: X509Certificate, trustedCaCerts: Array<X509Certificate?>): Boolean {
            // Return true iff either of the following is true:
            // 1) the cert is in the trustedCaCerts.
            // 2) the cert is issued by a trusted CA.

            // Check whether the cert is in the trustedCaCerts

            for (i in trustedCaCerts.indices) {
                // If the cert has the same SubjectDN
                // as a trusted CA, check whether
                // the two certs are the same.
                if (cert.subjectX500Principal == trustedCaCerts[i]!!.subjectX500Principal) {
                    if (cert == trustedCaCerts[i]) {
                        return true
                    }
                }
            }

            // Check whether the cert is issued by a trusted CA.
            // Signature verification is expensive. So we check
            // whether the cert is issued
            // by one of the trusted CAs if the above loop failed.
            for (i in trustedCaCerts.indices) {
                // If the issuer of the cert has the same name as
                // a trusted CA, check whether that trusted CA
                // actually issued the cert.
                if (cert.issuerX500Principal == trustedCaCerts[i]!!.issuerX500Principal) {
                    try {
                        cert.verify(trustedCaCerts[i]!!.publicKey)
                        return true
                    }
                    catch (e: Exception) {
                        // Do nothing.
                    }
                }
            }

            return false
        } //        public static X509Certificate[] getChainRoots(Certificate[] certs) {
        //            Vector<X509Certificate> result = new Vector<X509Certificate>(3);
        //            // choose a Vector size that seems reasonable
        //            for (int i = 0; i < certs.length - 1; i++) {
        //                if (!((X509Certificate) certs[i + 1]).getSubjectDN().equals(
        //                        ((X509Certificate) certs[i]).getIssuerDN())) {
        //                    // We've reached the end of a chain
        //                    result.addElement((X509Certificate) certs[i]);
        //                }
        //            }
        //
        //            // The final entry in the certs array is always
        //            // a "root" certificate
        //            result.addElement((X509Certificate) certs[certs.length - 1]);
        //            X509Certificate[] ret = new X509Certificate[result.size()];
        //            result.copyInto(ret);
        //
        //            return ret;
        //        }
    }


    object DSA {
        init {
            addProvider()
        }

        /**
         * Creates a X509 certificate holder object. 
         *
         *
         * 
         * Look at BCStyle for a list of all valid X500 Names.
         */
        fun createCertHolder(startDate: Date, expiryDate: Date,issuerName: X500Name, subjectName: X500Name, serialNumber: BigInteger,
            privateKey: DSAPrivateKeyParameters, publicKey: DSAPublicKeyParameters
        ): X509CertificateHolder? {
            val signatureAlgorithm = "SHA1withDSA"


            val sigAlgId = DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm)
            val digAlgId = DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId)


            val subjectPublicKeyInfo: SubjectPublicKeyInfo?
            val parameters = publicKey.parameters
            try {
                val encoded = SubjectPublicKeyInfo(
                    AlgorithmIdentifier(
                        X9ObjectIdentifiers.id_dsa, DSAParameter(
                            parameters.p, parameters.q, parameters.g
                        )
                    ), ASN1Integer(publicKey.y)
                ).getEncoded(ASN1Encoding.DER)

                val seq = ASN1Primitive.fromByteArray(encoded) as ASN1Sequence?
                subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(seq)
            }
            catch (e: IOException) {
                logger.error("Error during DSA.", e)
                return null
            }

            val v3CertBuilder = X509v3CertificateBuilder(
                issuerName, serialNumber, startDate, expiryDate, subjectName, subjectPublicKeyInfo
            )

            val contentSignerBuilder = BcDSAContentSignerBuilder(sigAlgId, digAlgId)

            val build: ContentSigner?
            try {
                build = contentSignerBuilder.build(privateKey)
            }
            catch (e: OperatorCreationException) {
                logger.error("Error creating certificate.", e)
                return null
            }

            return v3CertBuilder.build(build)
        }


        /**
         * Verifies that the certificate is legitimate.
         * 
         * 
         * MUST have BouncyCastle provider loaded by the security manager!
         * 
         * 
         * @return true if it was a valid cert.
         */
        fun validate(x509CertificateHolder: X509CertificateHolder): Boolean {
            try {
                // this is unique in that it verifies that the certificate is a LEGIT certificate, but not necessarily
                //  valid during this time period.

                val contentVerifierProvider = BcDSAContentVerifierProviderBuilder(
                    DefaultDigestAlgorithmIdentifierFinder()
                ).build(x509CertificateHolder)

                val signatureValid = x509CertificateHolder.isSignatureValid(contentVerifierProvider)

                if (!signatureValid) {
                    return false
                }


                val certificateFactory = CertificateFactory()
                val certificate = certificateFactory.engineGenerateCertificate(ByteArrayInputStream(x509CertificateHolder.encoded))
                // Note: this requires the BC provider to be loaded!
                if (certificate == null || certificate.publicKey == null) {
                    return false
                }

                // TODO: when validating the certificate, it is important to use a date from somewhere other than the host computer! (maybe use google? or something...)
                // this will validate the DATES of the certificate, to make sure the cert is valid during the correct time period.

                // Verify the TIME/DATE of the certificate
                (certificate as X509Certificate).checkValidity(Date())

                // if we get here, it means that our cert is LEGIT and VALID.
                return true
            }
            catch (t: Throwable) {
                throw RuntimeException(t)
            }
        }

        /**
         * Verifies the given x509 based signature against the OPTIONAL original public key. If not specified, then
         * the public key from the signature is used.
         * 
         * 
         * MUST have BouncyCastle provider loaded by the security manager!
         * 
         * 
         * @return true if the signature was valid.
         */
        fun verifySignature(signatureBytes: ByteArray, optionalOriginalPublicKey: DSAPublicKeyParameters?): Boolean {
            var asn1InputStream: ASN1InputStream? = null
            try {
                asn1InputStream = ASN1InputStream(ByteArrayInputStream(signatureBytes))
                val signatureASN = asn1InputStream.readObject()

                val seq = ASN1Sequence.getInstance(signatureASN) as BERSequence?
                val contentInfo = ContentInfo.getInstance(seq)

                // Extract certificates
                val newSignedData = SignedData.getInstance(contentInfo!!.content)

                val newSigIn: InputStream =
                    ByteArrayInputStream(newSignedData!!.certificates.parser().readObject().toASN1Primitive().getEncoded())

                val certificateFactory = CertificateFactory()
                val engineGenerateCert = certificateFactory.engineGenerateCertificate(newSigIn)

                val publicKey2 = engineGenerateCert.publicKey as BCDSAPublicKey

                if (optionalOriginalPublicKey != null) {
                    val params = publicKey2.params
                    val parameters = optionalOriginalPublicKey.parameters

                    if ((publicKey2.y != optionalOriginalPublicKey.y) || (params.p != parameters.p) || (params.q != parameters.q) || (params.g != parameters.g)) {
                        return false
                    }
                }

                // throws exception if it fails
                engineGenerateCert.verify(publicKey2)

                return true
            }
            catch (t: Throwable) {
                return false
            }
            finally {
                if (asn1InputStream != null) {
                    try {
                        asn1InputStream.close()
                    }
                    catch (e: IOException) {
                        logger.error("Error closing stream during DSA.", e)
                    }
                }
            }
        }
    }

    @Suppress("unused")
    object RSA {
        init {
            addProvider()
        }

        /**
         * Generate a cert that is signed by a CA cert.
         */
        @Throws(
            InvalidKeySpecException::class,
            InvalidKeyException::class,
            IOException::class,
            OperatorCreationException::class,
            CertificateException::class,
            NoSuchAlgorithmException::class,
            NoSuchProviderException::class,
            SignatureException::class
        )
        fun generateCert(
            factory: KeyFactory,
            startDate: Date?,
            expiryDate: Date?,
            issuerCert: X509Certificate,
            subject: String?,
            friendlyName: String,
            publicKey: RSAKeyParameters,
            signingCaKey: RSAPrivateCrtKeyParameters?
        ): X509Certificate? {
            return generateCert(
                factory,
                startDate,
                expiryDate,
                X500Name.getInstance(PrincipalUtil.getSubjectX509Principal(issuerCert)),
                X500Name(subject),
                friendlyName,
                publicKey,
                issuerCert,
                signingCaKey
            )
        }


        /**
         * Generate a cert that is self signed.
         */
        @Throws(
            InvalidKeySpecException::class,
            InvalidKeyException::class,
            IOException::class,
            OperatorCreationException::class,
            CertificateException::class,
            NoSuchAlgorithmException::class,
            NoSuchProviderException::class,
            SignatureException::class
        )
        fun generateCert(
            factory: KeyFactory,
            startDate: Date?,
            expiryDate: Date?,
            subject: String?,
            friendlyName: String,
            publicKey: RSAKeyParameters,
            privateKey: RSAPrivateCrtKeyParameters?
        ): X509Certificate? {
            return generateCert(
                factory, startDate, expiryDate, X500Name(subject), X500Name(subject), friendlyName, publicKey, null, privateKey
            )
        }



        @Throws(
            InvalidKeySpecException::class,
            IOException::class,
            InvalidKeyException::class,
            OperatorCreationException::class,
            CertificateException::class,
            NoSuchAlgorithmException::class,
            NoSuchProviderException::class,
            SignatureException::class
        )
        private fun generateCert(
            factory: KeyFactory, startDate: Date?, expiryDate: Date?,
            issuer: X500Name?, subject: X500Name?, friendlyName: String,
            certPublicKey: RSAKeyParameters,
            signingCertificate: X509Certificate?, signingPrivateKey: RSAPrivateCrtKeyParameters?
        ): X509Certificate? {
            val signatureAlgorithm = "SHA1withRSA"

            val sigAlgId = DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm) // specify it's RSA
            val digAlgId = DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId) // specify SHA

            // JCE format needed for the certificate - because getEncoded() is necessary...
            val jcePublicKey = convertToJCE(factory, certPublicKey)



            //            PrivateKey jcePrivateKey = convertToJCE(factory, publicKey, privateKey);
            val subjectPublicKeyInfo = createSubjectPublicKey(jcePublicKey)
            val certBuilder = X509v3CertificateBuilder(
                issuer, BigInteger.valueOf(System.currentTimeMillis()), startDate, expiryDate, subject, subjectPublicKeyInfo
            )



            //
            // extensions
            //
            val jcaX509ExtensionUtils = JcaX509ExtensionUtils() // SHA1
            val createSubjectKeyIdentifier = jcaX509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo)

            certBuilder.addExtension(
                Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier
            )

            if (signingCertificate != null) {
                val createAuthorityKeyIdentifier = jcaX509ExtensionUtils.createAuthorityKeyIdentifier(signingCertificate.publicKey)
                certBuilder.addExtension(
                    Extension.authorityKeyIdentifier, false, createAuthorityKeyIdentifier
                )
                //                new AuthorityKeyIdentifierStructure(signingCertificate));
            }

            certBuilder.addExtension(
                Extension.basicConstraints, true, BasicConstraints(false)
            )



            val signer = BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(signingPrivateKey)
            val certHolder = certBuilder.build(signer)

            val certificate = CertificateFactory().engineGenerateCertificate(
                ByteArrayInputStream(
                    certHolder.encoded
                )
            )

            if (certificate !is X509Certificate) {
                logger.error("Error generating certificate, it's the wrong type.")
                return null
            }

            if (signingCertificate != null) {
                certificate.verify(signingCertificate.publicKey)
            }
            else {
                certificate.verify(jcePublicKey)
            }

            if (certificate is PKCS12BagAttributeCarrier) {
                val bagAttr = certificate as PKCS12BagAttributeCarrier

                //
                // this is actually optional - but if you want to have control
                // over setting the friendly name this is the way to do it...
                //
                bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString(friendlyName))

                if (signingCertificate != null) {
                    bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, subjectPublicKeyInfo)
                }
            }

            return certificate


            //            //// subject name table.
//            //Hashtable<ASN1ObjectIdentifier, String> attrs = new Hashtable<ASN1ObjectIdentifier, String>();
//            //Vector<ASN1ObjectIdentifier>            order = new Vector<ASN1ObjectIdentifier>();
//            //
//            //attrs.put(BCStyle.C, "US");
//            //attrs.put(BCStyle.O, "Dorkbox");
//            //attrs.put(BCStyle.OU, "Dorkbox Certificate Authority");
//            //attrs.put(BCStyle.EmailAddress, "admin@dorkbox.com");
//            //
//            //order.addElement(BCStyle.C);
//            //order.addElement(BCStyle.O);
//            //order.addElement(BCStyle.OU);
//            //order.addElement(BCStyle.EmailAddress);
//            //
//            //X509Principal issuer = new X509Principal(order, attrs);
//            // MASTER CERT
//
//            //// signers name
//            //String  issuer = "C=US, O=dorkbox llc, OU=Dorkbox Certificate Authority";
//            //
//            //// subjects name - the same as we are self signed.
//            //String  subject = "C=US, O=dorkbox llc, OU=Dorkbox Certificate Authority";
        }

        @Throws(IOException::class)
        private fun createSubjectPublicKey(jcePublicKey: PublicKey): SubjectPublicKeyInfo? {
            var asn1InputStream: ASN1InputStream? = null
            try {
                asn1InputStream = ASN1InputStream(ByteArrayInputStream(jcePublicKey.encoded))
                return SubjectPublicKeyInfo.getInstance(asn1InputStream.readObject())
            }
            finally {
                if (asn1InputStream != null) {
                    asn1InputStream.close()
                }
            }
        }


        @Throws(NoSuchAlgorithmException::class, InvalidKeySpecException::class)
        fun convertToJCE(publicKey: RSAKeyParameters): PublicKey {
            val keyFactory = KeyFactory.getInstance("RSA")
            return convertToJCE(keyFactory, publicKey)
        }

        @Throws(InvalidKeySpecException::class)
        fun convertToJCE(keyFactory: KeyFactory, publicKey: RSAKeyParameters): PublicKey {
            return keyFactory.generatePublic(RSAPublicKeySpec(publicKey.modulus, publicKey.exponent))
        }

        fun convertToBC(publicKey: PublicKey?): RSAKeyParameters {
            val pubKey = RSAPublicKey.getInstance(publicKey)
            return RSAKeyParameters(false, pubKey!!.modulus, pubKey.publicExponent)
        }

        @Throws(InvalidKeySpecException::class, NoSuchAlgorithmException::class)
        fun convertToJCE(publicKey: RSAKeyParameters, privateKey: RSAPrivateCrtKeyParameters): PrivateKey? {
            val keyFactory = KeyFactory.getInstance("RSA")
            return convertToJCE(keyFactory, publicKey, privateKey)
        }

        @Throws(InvalidKeySpecException::class)
        fun convertToJCE(keyFactory: KeyFactory, publicKey: RSAKeyParameters, privateKey: RSAPrivateCrtKeyParameters): PrivateKey? {
            return keyFactory.generatePrivate(
                RSAPrivateCrtKeySpec(
                    publicKey.modulus,
                    publicKey.exponent,
                    privateKey.exponent,
                    privateKey.p,
                    privateKey.q,
                    privateKey.dp,
                    privateKey.dq,
                    privateKey.qInv
                )
            )
        }

        /**
         * Creates a X509 certificate holder object. 
         *
         *
         * 
         * Look at BCStyle for a list of all valid X500 Names.
         */
        fun createCertHolder(
            startDate: Date?, expiryDate: Date?,
            issuerName: X500Name?, subjectName: X500Name?, serialNumber: BigInteger,
            privateKey: RSAPrivateCrtKeyParameters?, publicKey: RSAKeyParameters
        ): X509CertificateHolder? {
            val signatureAlgorithm = "SHA256withRSA"


            val sigAlgId = DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm)
            val digAlgId = DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId)


            val subjectPublicKeyInfo: SubjectPublicKeyInfo?

            try {
                // JCE format needed for the certificate - because getEncoded() is necessary...
                val jcePublicKey = convertToJCE(publicKey)

                //            PrivateKey jcePrivateKey = convertToJCE(factory, publicKey, privateKey);
                subjectPublicKeyInfo = createSubjectPublicKey(jcePublicKey)
            }
            catch (e: Exception) {
                logger.error("Unable to create RSA keyA.", e)
                return null
            }


            try {
                val certBuilder = X509v3CertificateBuilder(
                    issuerName, serialNumber, startDate, expiryDate, subjectName, subjectPublicKeyInfo
                )
                //
                // extensions
                //
                val jcaX509ExtensionUtils = JcaX509ExtensionUtils() // SHA1
                val createSubjectKeyIdentifier = jcaX509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo)

                certBuilder.addExtension(
                    Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier
                )

                certBuilder.addExtension(
                    Extension.basicConstraints, true, BasicConstraints(false)
                )


                val hashSigner = BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKey)

                return certBuilder.build(hashSigner)
            }
            catch (e: Exception) {
                logger.error("Error generating certificate.", e)
                return null
            }
        }


        /**
         * Verifies that the certificate is legitimate.
         * 
         * 
         * MUST have BouncyCastle provider loaded by the security manager!
         * 
         * 
         * @return true if it was a valid cert.
         */
        fun validate(x509CertificateHolder: X509CertificateHolder): Boolean {
            try {
                // this is unique in that it verifies that the certificate is a LEGIT certificate, but not necessarily
                //  valid during this time period.

                val contentVerifierProvider =
                    BcRSAContentVerifierProviderBuilder(DefaultDigestAlgorithmIdentifierFinder()).build(x509CertificateHolder)

                val signatureValid = x509CertificateHolder.isSignatureValid(contentVerifierProvider)

                if (!signatureValid) {
                    return false
                }

                val certificate = CertificateFactory().engineGenerateCertificate(
                    ByteArrayInputStream(x509CertificateHolder.encoded)
                )

                // Note: this requires the BC provider to be loaded!
                if (certificate == null || certificate.publicKey == null) {
                    return false
                }

                if (certificate !is X509Certificate) {
                    return false
                }

                // TODO: when validating the certificate, it is important to use a date from somewhere other than the host computer! (maybe use google? or something...)
                // this will validate the DATES of the certificate, to make sure the cert is valid during the correct time period.

                // Verify the TIME/DATE of the certificate
                certificate.checkValidity(Date())

                // if we get here, it means that our cert is LEGIT and VALID.
                return true
            }
            catch (t: Throwable) {
                logger.error("Error validating certificate.", t)
                return false
            }
        }

        /**
         * Verifies the given x509 based signature against the OPTIONAL original public key. If not specified, then
         * the public key from the signature is used.
         * 
         * 
         * MUST have BouncyCastle provider loaded by the security manager!
         * 
         * 
         * @return true if the signature was valid.
         */
        fun verifySignature(signatureBytes: ByteArray, publicKey: RSAKeyParameters?): Boolean {
            var asn1InputStream: ASN1InputStream? = null
            try {
                asn1InputStream = ASN1InputStream(ByteArrayInputStream(signatureBytes))
                val signatureASN = asn1InputStream.readObject()
                val seq = ASN1Sequence.getInstance(signatureASN) as BERSequence?
                val contentInfo = ContentInfo.getInstance(seq)

                // Extract certificates
                val newSignedData = SignedData.getInstance(contentInfo!!.content)

                val newSigIn: InputStream =
                    ByteArrayInputStream(newSignedData!!.certificates.parser().readObject().toASN1Primitive().getEncoded())

                val certFactory = CertificateFactory()
                val certificate = certFactory.engineGenerateCertificate(newSigIn)

                val publicKey2 = certificate.publicKey as BCRSAPublicKey

                if (publicKey != null) {
                    if (publicKey.modulus != publicKey2.modulus || publicKey.exponent != publicKey2.publicExponent) {
                        return false
                    }
                }

                // throws exception if it fails.
                certificate.verify(publicKey2)

                return true
            }
            catch (t: Throwable) {
                logger.error("Error validating certificate.", t)
                return false
            }
            finally {
                if (asn1InputStream != null) {
                    try {
                        asn1InputStream.close()
                    }
                    catch (e: IOException) {
                        logger.error("Error closing stream during RSA.", e)
                    }
                }
            }
        }

        //        public static class CertificateAuthority {
        //            public static X509Certificate generateCert(KeyFactory factory, Date startDate, Date expiryDate,
        //                                                         String  issuer, String subject, String friendlyName,
        //                                                         RSAKeyParameters publicKey, RSAPrivateCrtKeyParameters privateKey) throws InvalidKeySpecException, IOException, InvalidKeyException, OperatorCreationException {
        //
        //                return CryptoX509.RSA.generateCert(factory, startDate, expiryDate, new X500Name(issuer), new X500Name(subject), friendlyName, publicKey, privateKey, null);
        //            }
        //
        //            public static X509Certificate generateCert(KeyFactory factory, Date startDate, Date expiryDate,
        //                                                         X509Principal issuer, String subject, String friendlyName,
        //                                                         RSAKeyParameters publicKey, RSAPrivateCrtKeyParameters privateKey) throws InvalidKeySpecException, InvalidKeyException, IOException, OperatorCreationException {
        //
        //                return CryptoX509.RSA.generateCert(factory, startDate, expiryDate, X500Name.getInstance(issuer), new X500Name(subject), friendlyName, publicKey, privateKey, null);
        //            }
        //        }
        //
        //
        //        public static class IntermediateAuthority {
        //            public static X509Certificate generateCert(KeyFactory factory, Date startDate, Date expiryDate,
        //                                                         String  issuer, String subject, String friendlyName,
        //                                                         RSAKeyParameters publicKey, RSAPrivateCrtKeyParameters privateKey,
        //                                                         X509Certificate caCertificate) throws InvalidKeySpecException, IOException, InvalidKeyException, OperatorCreationException {
        //
        //                return CryptoX509.RSA.generateCert(factory, startDate, expiryDate, new X500Name(issuer), new X500Name(subject), friendlyName, publicKey, privateKey, caCertificate);
        //            }
        //
        //            public static X509Certificate generateCert(KeyFactory factory, Date startDate, Date expiryDate,
        //                                                           X509Principal issuer, String subject, String friendlyName,
        //                                                           RSAKeyParameters publicKey, RSAPrivateCrtKeyParameters privateKey,
        //                                                           X509Certificate caCertificate) throws InvalidKeySpecException, InvalidKeyException, IOException, OperatorCreationException {
        //
        //                return CryptoX509.RSA.generateCert(factory, startDate, expiryDate, X500Name.getInstance(issuer), new X500Name(subject), friendlyName, publicKey, privateKey, caCertificate);
        //            }
        //        }
        //
        object CertificateAuthrority {
            fun generateCert(
                factory: KeyFactory, startDate: Date?, endDate: Date?,
                subject: String?, friendlyName: String,
                publicKey: RSAKeyParameters, privateKey: RSAPrivateCrtKeyParameters?
            ): X509Certificate? {
                val signatureAlgorithm = "SHA1withRSA"

                val sigAlgId = DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm) // specify it's RSA
                val digAlgId = DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId) // specify SHA

                try {
                    // JCE format needed for the certificate - because getEncoded() is necessary...
                    val jcePublicKey = convertToJCE(factory, publicKey)

                    //                PrivateKey jcePrivateKey = convertToJCE(factory, publicKey, privateKey);
                    val subjectPublicKeyInfo = createSubjectPublicKey(jcePublicKey)
                    val certBuilder = X509v3CertificateBuilder(
                        X500Name(subject),
                        BigInteger.valueOf(System.currentTimeMillis()),
                        startDate,
                        endDate,
                        X500Name(subject),
                        subjectPublicKeyInfo
                    )

                    //
                    // extensions
                    //
                    val jcaX509ExtensionUtils = JcaX509ExtensionUtils() // SHA1
                    val createSubjectKeyIdentifier = jcaX509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo)

                    certBuilder.addExtension(
                        Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier
                    )

                    certBuilder.addExtension(
                        Extension.basicConstraints, true, BasicConstraints(1)
                    )


                    val hashSigner = BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKey)
                    val certHolder = certBuilder.build(hashSigner)

                    val certificate = CertificateFactory().engineGenerateCertificate(
                        ByteArrayInputStream(certHolder.encoded)
                    )

                    if (certificate !is X509Certificate) {
                        logger.error("Error generating certificate, it's the wrong type.")
                        return null
                    }

                    certificate.verify(jcePublicKey)


                    if (certificate is PKCS12BagAttributeCarrier) {
                        val bagAttr = certificate as PKCS12BagAttributeCarrier

                        //
                        // this is actually optional - but if you want to have control
                        // over setting the friendly name this is the way to do it...
                        //
                        bagAttr.setBagAttribute(
                            PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString(friendlyName)
                        )
                    }

                    return certificate
                }
                catch (e: Exception) {
                    logger.error("Error generating certificate.", e)
                    return null
                }
            }
        }

        object SelfSigned {
            fun generateCert(
                factory: KeyFactory, startDate: Date?, endDate: Date?,
                subject: String?, friendlyName: String,
                publicKey: RSAKeyParameters, privateKey: RSAPrivateCrtKeyParameters?
            ): X509Certificate? {
                val signatureAlgorithm = "SHA1withRSA"

                val sigAlgId = DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm) // specify it's RSA
                val digAlgId = DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId) // specify SHA

                try {
                    // JCE format needed for the certificate - because getEncoded() is necessary...
                    val jcePublicKey = convertToJCE(factory, publicKey)

                    //                PrivateKey jcePrivateKey = convertToJCE(factory, publicKey, privateKey);
                    val subjectPublicKeyInfo = createSubjectPublicKey(jcePublicKey)
                    val certBuilder = X509v3CertificateBuilder(
                        X500Name(subject),
                        BigInteger.valueOf(System.currentTimeMillis()),
                        startDate,
                        endDate,
                        X500Name(subject),
                        subjectPublicKeyInfo
                    )

                    //
                    // extensions
                    //
                    val jcaX509ExtensionUtils = JcaX509ExtensionUtils() // SHA1
                    val createSubjectKeyIdentifier = jcaX509ExtensionUtils.createSubjectKeyIdentifier(subjectPublicKeyInfo)

                    certBuilder.addExtension(
                        Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier
                    )

                    certBuilder.addExtension(
                        Extension.basicConstraints, true, BasicConstraints(false)
                    )


                    val hashSigner = BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKey)
                    val certHolder = certBuilder.build(hashSigner)

                    val certificate = CertificateFactory().engineGenerateCertificate(
                        ByteArrayInputStream(
                            certHolder.encoded
                        )
                    )

                    if (certificate !is X509Certificate) {
                        logger.error("Error generating certificate, it's the wrong type.")
                        return null
                    }

                    certificate.verify(jcePublicKey)


                    if (certificate is PKCS12BagAttributeCarrier) {
                        val bagAttr = certificate as PKCS12BagAttributeCarrier

                        //
                        // this is actually optional - but if you want to have control
                        // over setting the friendly name this is the way to do it...
                        //
                        bagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString(friendlyName))
                    }


                    return certificate
                }
                catch (e: Exception) {
                    logger.error("Error generating certificate.", e)
                    return null
                }
            }
        }
    }

    object ECDSA {
        init {
            // make sure we only add it once (in case it's added elsewhere...)
            val provider = Security.getProvider("BC")
            if (provider == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        /**
         * Creates a X509 certificate holder object.
         */
        fun createCertHolder(
            digestName: String?,
            startDate: Date?, expiryDate: Date?,
            issuerName: X500Name?, subjectName: X500Name?,
            serialNumber: BigInteger,
            privateKey: ECPrivateKeyParameters?,
            publicKey: ECPublicKeyParameters
        ): X509CertificateHolder? {
            val signatureAlgorithm = digestName + "withECDSA"


            // we WANT the ECparameterSpec to be null, so it's created from the public key
            val pubKey = JCEECPublicKey("EC", publicKey, null as ECParameterSpec?)

            val sigAlgId = DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm)
            val digAlgId = DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId)

            val subjectPublicKeyInfo: SubjectPublicKeyInfo?

            try {
                val encoded = pubKey.getEncoded()
                val seq = ASN1Primitive.fromByteArray(encoded) as ASN1Sequence?
                subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(seq)
            }
            catch (e: IOException) {
                logger.error("Unable to perform DSA.", e)
                return null
            }

            val v3CertBuilder = X509v3CertificateBuilder(
                issuerName, serialNumber, startDate, expiryDate, subjectName, subjectPublicKeyInfo
            )

            val contentSignerBuilder = BcECDSAContentSignerBuilder(sigAlgId, digAlgId)

            val build: ContentSigner?
            try {
                build = contentSignerBuilder.build(privateKey)
            }
            catch (e: OperatorCreationException) {
                logger.error("Error creating certificate.", e)
                return null
            }

            return v3CertBuilder.build(build)
        }

        /**
         * Verifies that the certificate is legitimate.
         * 
         * 
         * MUST have BouncyCastle provider loaded by the security manager!
         * 
         * 
         * @return true if it was a valid cert.
         */
        fun validate(x509CertificateHolder: X509CertificateHolder): Boolean {
            try {
                // this is unique in that it verifies that the certificate is a LEGIT certificate, but not necessarily
                //  valid during this time period.

                val contentVerifierProvider = BcECDSAContentVerifierProviderBuilder(
                    DefaultDigestAlgorithmIdentifierFinder()
                ).build(x509CertificateHolder)

                val signatureValid = x509CertificateHolder.isSignatureValid(contentVerifierProvider)

                if (!signatureValid) {
                    return false
                }

                val certFactory = CertificateFactory()
                val certificate = certFactory.engineGenerateCertificate(ByteArrayInputStream(x509CertificateHolder.encoded))

                // Note: this requires the BC provider to be loaded!
                if (certificate == null || certificate.publicKey == null) {
                    return false
                }

                // TODO: when validating the certificate, it is important to use a date from somewhere other than the host computer! (maybe use google? or something...)
                // this will validate the DATES of the certificate, to make sure the cert is valid during the correct time period.

                // Verify the TIME/DATE of the certificate
                (certificate as X509Certificate).checkValidity(Date())

                // if we get here, it means that our cert is LEGIT and VALID.
                return true
            }
            catch (t: Throwable) {
                logger.error("Error validating certificate.", t)
                return false
            }
        }

        /**
         * Verifies the given x509 based signature against the OPTIONAL original public key. If not specified, then
         * the public key from the signature is used.
         * 
         * 
         * MUST have BouncyCastle provider loaded by the security manager!
         * 
         * 
         * @return true if the signature was valid.
         */
        fun verifySignature(signatureBytes: ByteArray, optionalOriginalPublicKey: ECPublicKeyParameters?): Boolean {
            var asn1InputStream: ASN1InputStream? = null
            try {
                asn1InputStream = ASN1InputStream(ByteArrayInputStream(signatureBytes))
                val signatureASN = asn1InputStream.readObject()
                val seq = ASN1Sequence.getInstance(signatureASN) as BERSequence?
                val contentInfo = ContentInfo.getInstance(seq)

                // Extract certificates
                val newSignedData = SignedData.getInstance(contentInfo!!.content)

                val newSigIn: InputStream =
                    ByteArrayInputStream(newSignedData!!.certificates.parser().readObject().toASN1Primitive().getEncoded())

                val certificateFactory = CertificateFactory()
                val certificate = certificateFactory.engineGenerateCertificate(newSigIn)

                var publicKey2 = certificate.publicKey

                if (optionalOriginalPublicKey != null) {
                    val parameters = optionalOriginalPublicKey.parameters
                    val ecParameterSpec = ECParameterSpec(parameters.curve, parameters.g, parameters.n, parameters.h)
                    val origPublicKey = BCECPublicKey("EC", optionalOriginalPublicKey, ecParameterSpec, null)

                    val equals = origPublicKey == publicKey2
                    if (!equals) {
                        return false
                    }

                    publicKey2 = origPublicKey
                }

                // throws an exception if not valid!
                certificate.verify(publicKey2)

                return true
            }
            catch (t: Throwable) {
                logger.error("Error validating certificate.", t)
                return false
            }
            finally {
                if (asn1InputStream != null) {
                    try {
                        asn1InputStream.close()
                    }
                    catch (e: IOException) {
                        logger.error("Error during ECDSA.", e)
                    }
                }
            }
        }
    }
}
