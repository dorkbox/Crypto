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
package dorkbox.crypto.signers

import dorkbox.crypto.Crypto
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.crypto.Signer
import org.bouncycastle.crypto.signers.DSADigestSigner
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.jcajce.provider.util.DigestFactory
import org.bouncycastle.operator.OperatorCreationException
import org.bouncycastle.operator.bc.BcContentSignerBuilder

class BcECDSAContentSignerBuilder : BcContentSignerBuilder {
    companion object {
        /**
         * Gets the version number.
         */
        const val version = Crypto.version
    }

    constructor(sigAlgId: AlgorithmIdentifier?, digAlgId: AlgorithmIdentifier?) : super(sigAlgId, digAlgId)

    @Throws(OperatorCreationException::class)
    override fun createSigner(sigAlgId: AlgorithmIdentifier?, digAlgId: AlgorithmIdentifier): Signer {
        val digest = DigestFactory.getDigest(digAlgId.algorithm.id) // SHA1, SHA512, etc
        return DSADigestSigner(ECDSASigner(), digest)
    }
}
