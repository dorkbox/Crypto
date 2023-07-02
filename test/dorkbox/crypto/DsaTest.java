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
package dorkbox.crypto;

import static org.junit.Assert.fail;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.junit.Test;


@SuppressWarnings("deprecation")
public class DsaTest {
    private static String entropySeed = "asdjhaffasttjjhgpx600gn,-356268909087s0dfgkjh255124515hasdg87";

    // Note: this is here just for keeping track of how this is done. This should NOT be used, and instead ECC crypto used instead.
    @Test
    public void Dsa() {
        byte[] bytes = "hello, my name is inigo montoya".getBytes();

        AsymmetricCipherKeyPair generateKeyPair = CryptoDSA.generateKeyPair(new SecureRandom(entropySeed.getBytes()), 1024);
        DSAPrivateKeyParameters privateKey = (DSAPrivateKeyParameters) generateKeyPair.getPrivate();
        DSAPublicKeyParameters publicKey = (DSAPublicKeyParameters) generateKeyPair.getPublic();


        BigInteger[] signature = CryptoDSA.generateSignature(privateKey, new SecureRandom(entropySeed.getBytes()), bytes);

        boolean verify1 = CryptoDSA.verifySignature(publicKey, bytes, signature);

        if (!verify1) {
            fail("failed signature verification");
        }


        byte[] bytes2 = "hello, my name is inigo montoya FAILED VERSION".getBytes();

        if (Arrays.equals(bytes, bytes2)) {
            fail("failed to create different byte arrays for testing bad messages");
        }



        boolean verify2 = CryptoDSA.verifySignature(publicKey, bytes2, signature);

        if (verify2) {
            fail("failed signature verification with bad message");
        }
    }

    @Test
    public void DsaJceSerializaion() throws IOException {

        AsymmetricCipherKeyPair generateKeyPair = CryptoDSA.generateKeyPair(new SecureRandom(entropySeed.getBytes()), 1024);
        DSAPrivateKeyParameters privateKey = (DSAPrivateKeyParameters) generateKeyPair.getPrivate();
        DSAPublicKeyParameters publicKey = (DSAPublicKeyParameters) generateKeyPair.getPublic();


        // public key as bytes.
        DSAParameters parameters = publicKey.getParameters();
        byte[] bs = new SubjectPublicKeyInfo(
                                 new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa,
                                                         new DSAParameter(parameters.getP(), parameters.getQ(), parameters.getG()).toASN1Primitive()),
                                 new ASN1Integer(publicKey.getY())).getEncoded();



        parameters = privateKey.getParameters();
        byte[] bs2 = new PrivateKeyInfo(
                                new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa,
                                                        new DSAParameter(parameters.getP(), parameters.getQ(), parameters.getG()).toASN1Primitive()),
                                new ASN1Integer(privateKey.getX())).getEncoded();





        DSAPrivateKeyParameters privateKey2 = (DSAPrivateKeyParameters) PrivateKeyFactory.createKey(bs2);
        DSAPublicKeyParameters publicKey2 = (DSAPublicKeyParameters) PublicKeyFactory.createKey(bs);



        // test via signing
        byte[] bytes = "hello, my name is inigo montoya".getBytes();


        BigInteger[] signature = CryptoDSA.generateSignature(privateKey, new SecureRandom(entropySeed.getBytes()), bytes);

        boolean verify1 = CryptoDSA.verifySignature(publicKey, bytes, signature);

        if (!verify1) {
            fail("failed signature verification");
        }


        boolean verify2 = CryptoDSA.verifySignature(publicKey2, bytes, signature);

        if (!verify2) {
            fail("failed signature verification");
        }



        // now reverse who signs what.
        BigInteger[] signatureB = CryptoDSA.generateSignature(privateKey2, new SecureRandom(entropySeed.getBytes()), bytes);

        boolean verifyB1 = CryptoDSA.verifySignature(publicKey, bytes, signatureB);

        if (!verifyB1) {
            fail("failed signature verification");
        }


        boolean verifyB2 = CryptoDSA.verifySignature(publicKey2, bytes, signatureB);

        if (!verifyB2) {
            fail("failed signature verification");
        }
    }

}
