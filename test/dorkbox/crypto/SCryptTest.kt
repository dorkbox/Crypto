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

import dorkbox.bytes.toNoPrefixHexString
import org.junit.Assert
import org.junit.Test
import java.io.IOException
import java.security.GeneralSecurityException

class SCryptTest {
    @Test
    @Throws(IOException::class, GeneralSecurityException::class)
    fun SCrypt() {
        var P: ByteArray
        var S: ByteArray
        var N: Int
        var r: Int
        var p: Int
        var dkLen: Int
        var DK: String

        // empty key & salt test missing because unsupported by JCE
        P = "password".toByteArray(charset("UTF-8"))
        S = "NaCl".toByteArray(charset("UTF-8"))
        N = 1024
        r = 8
        p = 16
        dkLen = 64
        DK = "FDBABE1C9D3472007856E7190D01E9FE7C6AD7CBC8237830E77376634B3731622EAF30D92E22A3886FF109279D9830DAC727AFB94A83EE6D8360CBDFA2CC0640"
        Assert.assertEquals(DK, CryptoSCrypt.encrypt(P, S, N, r, p, dkLen).toNoPrefixHexString(toUpperCase = true))


        P = "pleaseletmein".toByteArray(charset("UTF-8"))
        S = "SodiumChloride".toByteArray(charset("UTF-8"))
        N = 16384
        r = 8
        p = 1
        dkLen = 64
        DK = "7023BDCB3AFD7348461C06CD81FD38EBFDA8FBBA904F8E3EA9B543F6545DA1F2D5432955613F0FCF62D49705242A9AF9E61E85DC0D651E40DFCF017B45575887"
        Assert.assertEquals(DK, CryptoSCrypt.encrypt(P, S, N, r, p, dkLen).toNoPrefixHexString(toUpperCase = true))


        P = "pleaseletmein".toByteArray(charset("UTF-8"))
        S = "SodiumChloride".toByteArray(charset("UTF-8"))
        N = 1048576
        r = 8
        p = 1
        dkLen = 64
        DK = "2101CB9B6A511AAEADDBBE09CF70F881EC568D574A2FFD4DABE5EE9820ADAA478E56FD8F4BA5D09FFA1C6D927C40F4C337304049E8A952FBCBF45C6FA77A41A4"
        Assert.assertEquals(DK, CryptoSCrypt.encrypt(P, S, N, r, p, dkLen).toNoPrefixHexString(toUpperCase = true))
    }
}
