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

import dorkbox.crypto.BCrypt.Companion.checkPassword
import dorkbox.crypto.BCrypt.Companion.generateSalt
import dorkbox.crypto.BCrypt.Companion.hashPassword
import junit.framework.TestCase

// Copyright (c) 2006 Damien Miller <djm@mindrot.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

/**
 * JUnit unit tests for BCrypt routines
 * @author Damien Miller
 * @version 0.2
 */
class TestBCrypt : TestCase() {
    var test_vectors: Array<Array<String>?>? = arrayOf<Array<String>?>(
        arrayOf<String>(
            "", "$2a$06\$DCq7YPn5Rq63x1Lad4cll.", "$2a$06\$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."
        ),
        arrayOf<String>(
            "", "$2a$08\$HqWuK6/Ng6sg9gQzbLrgb.", "$2a$08\$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"
        ),
        arrayOf<String>(
            "", "$2a$10\$k1wbIrmNyFAPwPVPSVa/ze", "$2a$10\$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW"
        ),
        arrayOf<String>(
            "", "$2a$12\$k42ZFHFWqBp3vWli.nIn8u", "$2a$12\$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"
        ),
        arrayOf<String>(
            "a", "$2a$06\$m0CrhHm10qJ3lXRY.5zDGO", "$2a$06\$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"
        ),
        arrayOf<String>(
            "a", "$2a$08\$cfcvVd2aQ8CMvoMpP2EBfe", "$2a$08\$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V."
        ),
        arrayOf<String>(
            "a", "$2a$10\$k87L/MF28Q673VKh8/cPi.", "$2a$10\$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"
        ),
        arrayOf<String>(
            "a", "$2a$12$8NJH3LsPrANStV6XtBakCe", "$2a$12$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS"
        ),
        arrayOf<String>(
            "abc", "$2a$06\$If6bvum7DFjUnE9p2uDeDu", "$2a$06\$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"
        ),
        arrayOf<String>(
            "abc", "$2a$08\$Ro0CUfOqk6cXEKf3dyaM7O", "$2a$08\$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm"
        ),
        arrayOf<String>(
            "abc", "$2a$10\$WvvTPHKwdBJ3uk0Z37EMR.", "$2a$10\$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"
        ),
        arrayOf<String>(
            "abc", "$2a$12\$EXRkfkdmXn2gzds2SSitu.", "$2a$12\$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q"
        ),
        arrayOf<String>(
            "abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGu", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"
        ),
        arrayOf<String>(
            "abcdefghijklmnopqrstuvwxyz", "$2a$08\$aTsUwsyowQuzRrDqFflhge", "$2a$08\$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."
        ),
        arrayOf<String>(
            "abcdefghijklmnopqrstuvwxyz", "$2a$10\$fVH8e28OQRj9tqiDXs1e1u", "$2a$10\$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"
        ),
        arrayOf<String>(
            "abcdefghijklmnopqrstuvwxyz", "$2a$12\$D4G5f18o7aMMfwasBL7Gpu", "$2a$12\$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"
        ),
        arrayOf<String>(
            "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$06\$fPIsBO8qRqkjj273rfaOI.",
            "$2a$06\$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"
        ),
        arrayOf<String>(
            "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$08\$Eq2r4G/76Wv39MzSX262hu",
            "$2a$08\$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"
        ),
        arrayOf<String>(
            "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$10\$LgfYWkbzEvQ4JakH7rOvHe",
            "$2a$10\$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"
        ),
        arrayOf<String>(
            "~!@#$%^&*()      ~!@#$%^&*()PNBFRD",
            "$2a$12\$WApznUOJfkEGSmYRfnkrPO",
            "$2a$12\$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"
        ),
    )

    /**
     * Test method for 'BCrypt.hashpw(String, String)'
     */
    fun testHashpw() {
        print("BCrypt.hashpw(): ")
        for (i in test_vectors!!.indices) {
            val plain = test_vectors!![i]!![0]
            val salt = test_vectors!![i]!![1]
            val expected = test_vectors!![i]!![2]
            val hashed = BCrypt.hashPassword(plain, salt)
            TestCase.assertEquals(hashed, expected)
            print(".")
        }
        println("")
    }

    /**
     * Test method for 'BCrypt.gensalt(int)'
     */
    fun testGensaltInt() {
        print("BCrypt.gensalt(log_rounds):")
        for (i in 4..12) {
            print(" $i:")
            var j = 0
            while (j < test_vectors!!.size) {
                val plain = test_vectors!![j]!![0]
                val salt = generateSalt(i)
                val hashed1 = hashPassword(plain, salt)
                val hashed2 = hashPassword(plain, hashed1)
                TestCase.assertEquals(hashed1, hashed2)
                print(".")
                j += 4
            }
        }
        println("")
    }

    /**
     * Test method for 'BCrypt.gensalt()'
     */
    fun testGensalt() {
        print("BCrypt.gensalt(): ")
        var i = 0
        while (i < test_vectors!!.size) {
            val plain = test_vectors!![i]!![0]
            val salt = generateSalt()
            val hashed1 = hashPassword(plain, salt)
            val hashed2 = hashPassword(plain, hashed1)
            TestCase.assertEquals(hashed1, hashed2)
            print(".")
            i += 4
        }
        println("")
    }

    /**
     * Test method for 'BCrypt.checkpw(String, String)'
     * expecting success
     */
    fun testCheckpw_success() {
        print("BCrypt.checkpw w/ good passwords: ")
        for (i in test_vectors!!.indices) {
            val plain = test_vectors!![i]!![0]
            val expected = test_vectors!![i]!![2]
            assertTrue(checkPassword(plain, expected))
            print(".")
        }
        println("")
    }

    /**
     * Test method for 'BCrypt.checkpw(String, String)'
     * expecting failure
     */
    fun testCheckpw_failure() {
        print("BCrypt.checkpw w/ bad passwords: ")
        for (i in test_vectors!!.indices) {
            val broken_index = (i + 4) % test_vectors!!.size
            val plain = test_vectors!![i]!![0]
            val expected = test_vectors!![broken_index]!![2]
            assertFalse(checkPassword(plain, expected))
            print(".")
        }
        println("")
    }

    /**
     * Test for correct hashing of non-US-ASCII passwords
     */
    fun testInternationalChars() {
        print("BCrypt.hashpw w/ international chars: ")
        val pw1 = "\u2605\u2605\u2605\u2605\u2605\u2605\u2605\u2605"
        val pw2 = "????????"

        val h1 = hashPassword(pw1, generateSalt())
        assertFalse(checkPassword(pw2, h1))
        print(".")

        val h2 = hashPassword(pw2, generateSalt())
        assertFalse(checkPassword(pw1, h2))
        print(".")
        println("")
    }
}
