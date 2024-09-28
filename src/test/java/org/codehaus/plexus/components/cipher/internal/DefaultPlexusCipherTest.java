/*
 * Copyright (c) 2008 Sonatype, Inc. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package org.codehaus.plexus.components.cipher.internal;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;

import org.codehaus.plexus.components.cipher.PlexusCipher;
import org.codehaus.plexus.components.cipher.PlexusCipherException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test the Plexus Cipher container
 *
 * @author Oleg Gusakov
 */
class DefaultPlexusCipherTest {
    private final String passPhrase = "testtest";
    final String str = "my testing phrase";
    PlexusCipher pc;

    static String[] ALG = new String[] {AESCBCPKCS5Padding.CIPHER_ALG, AESGCMNoPadding.CIPHER_ALG};

    @BeforeEach
    void prepare() {
        HashMap<String, Cipher> ciphers = new HashMap<>();
        ciphers.put(AESCBCPKCS5Padding.CIPHER_ALG, new AESGCMNoPadding());
        ciphers.put(AESGCMNoPadding.CIPHER_ALG, new AESGCMNoPadding());
        pc = new DefaultPlexusCipher(ciphers);
    }

    @Test
    void testAvailableCiphers() {
        HashSet<String> wanted = new HashSet<>(Arrays.asList(ALG));
        assertEquals(wanted, pc.availableCiphers());
    }

    @Test
    void testIsEncryptedString() {
        String noBraces = "This is a test";
        String normalBraces = "Comment {This is a test} other comment with a: }";
        String escapedBraces = "\\{This is a test\\}";
        String mixedBraces = "Comment {foo\\{This is a test\\}} other comment with a: }";
        assertFalse(pc.isEncryptedString(noBraces));
        assertTrue(pc.isEncryptedString(normalBraces));
        assertFalse(pc.isEncryptedString(escapedBraces));
        assertTrue(pc.isEncryptedString(mixedBraces));
    }

    @Test
    void testUnDecorate_BracesPermutations() throws PlexusCipherException {
        String noBraces = "This is a test";
        String normalBraces = "Comment {This is a test} other comment with a: }";
        String mixedBraces = "Comment {foo\\{This is a test\\}} other comment with a: }";
        assertEquals(noBraces, pc.unDecorate(normalBraces));
        assertEquals("foo\\{" + noBraces + "\\}", pc.unDecorate(mixedBraces));
    }

    @Test
    void testAllAlgorithmExists() throws Exception {
        String[] res = DefaultPlexusCipher.getCryptoImpls("Cipher");
        assertNotNull(res, "No Cipher providers found in the current environment");
        // System.out.println("\n=== Available ciphers :");
        // for (String re : res) {
        //    System.out.println(re);
        // }
        // System.out.println("====================");
        HashSet<String> algs = new HashSet<>(pc.availableCiphers());
        for (String provider : res) {
            algs.remove(provider);
        }
        if (!algs.isEmpty()) {
            throw new Exception("Cannot find algorithms " + algs + " in the current environment.");
        }
    }

    @ParameterizedTest
    @FieldSource("ALG")
    void testEncrypt(String alg) throws Exception {
        String xRes = pc.encrypt(alg, str, passPhrase);
        // System.out.println(xRes);
        String res = pc.decrypt(alg, xRes, passPhrase);
        assertEquals(str, res, "Encryption/Decryption did not produce desired result");
    }

    @ParameterizedTest
    @FieldSource("ALG")
    void testEncryptVariableLengths(String alg) throws Exception {
        String pass = "g";
        for (int i = 0; i < 64; i++) {
            pass = pass + 'a';
            String xRes = pc.encrypt(alg, str, pass);
            // System.out.println(pass.length() + ": " + xRes);
            String res = pc.decrypt(alg, xRes, pass);
            assertEquals(str, res, "Encryption/Decryption did not produce desired result");
        }
    }

    @ParameterizedTest
    @FieldSource("ALG")
    void testDecrypt(String alg) {
        assertDoesNotThrow(
                () -> {
                    String encStr = pc.encrypt(alg, str, passPhrase);
                    String res = pc.decrypt(alg, encStr, passPhrase);
                    assertEquals(str, res, "Decryption did not produce desired result");
                },
                "Decryption failed: ");
    }

    @Test
    void testDecorate() {
        String res = pc.decorate("aaa");
        assertEquals("{aaa}", res, "Decoration failed");
    }

    @Test
    void testUnDecorate() throws Exception {
        String res = pc.unDecorate("{aaa}");
        assertEquals("aaa", res, "Decoration failed");
    }

    @ParameterizedTest
    @FieldSource("ALG")
    void testEncryptAndDecorate(String alg) throws Exception {
        String res = pc.encryptAndDecorate(alg, "my-password", "12345678");
        assertEquals('{', res.charAt(0));
        assertEquals('}', res.charAt(res.length() - 1));
    }
}
