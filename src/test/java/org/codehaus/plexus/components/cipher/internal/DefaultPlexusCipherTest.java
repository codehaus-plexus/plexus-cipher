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

import org.codehaus.plexus.components.cipher.PlexusCipher;
import org.codehaus.plexus.components.cipher.PlexusCipherException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

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

    final String encStr = "RRvejxJ+wksH/kWnYfun/GeFoPKh6JHcA2dmxMOIraZiIuLISplmdyvl2Sq04rpP";
    PlexusCipher pc;

    @BeforeEach
    void prepare() {
        pc = new DefaultPlexusCipher();
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

    // -------------------------------------------------------------

    @Test
    void testDefaultAlgorithmExists() throws Exception {
        String[] res = DefaultPlexusCipher.getCryptoImpls("Cipher");
        assertNotNull(res, "No Cipher providers found in the current environment");

        System.out.println("\n=== Available ciphers :");
        for (String re : res) {
            System.out.println(re);
        }
        System.out.println("====================");

        for (String provider : res) {
            if (PBECipher.KEY_ALG.equalsIgnoreCase(provider)) return;
        }

        throw new Exception("Cannot find default algorithm " + PBECipher.KEY_ALG + " in the current environment.");
    }

    // -------------------------------------------------------------

    @Disabled("This test is not really a test")
    @Test
    void stestFindDefaultAlgorithm() {
        String[] res = DefaultPlexusCipher.getServiceTypes();
        assertNotNull(res, "No service types found in the current environment");

        String[] impls = DefaultPlexusCipher.getCryptoImpls("Cipher");
        assertNotNull(impls, "No Cipher providers found in the current environment");

        for (String impl : impls)
            try {
                System.out.print(impl);
                pc.encrypt(str, passPhrase);
                System.out.println("------------------> Success !!!!!!");
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
    }

    // -------------------------------------------------------------
    @Test
    void testEncrypt() throws Exception {
        String xRes = pc.encrypt(str, passPhrase);

        System.out.println(xRes);

        String res = pc.decrypt(xRes, passPhrase);

        assertEquals(str, res, "Encryption/Decryption did not produce desired result");
    }

    // -------------------------------------------------------------

    @Test
    void testEncryptVariableLengths() throws Exception {
        String pass = "g";

        for (int i = 0; i < 64; i++) {
            pass = pass + 'a';

            String xRes = pc.encrypt(str, pass);

            System.out.println(pass.length() + ": " + xRes);

            String res = pc.decrypt(xRes, pass);

            assertEquals(str, res, "Encryption/Decryption did not produce desired result");
        }
    }

    @Test
    void testDecrypt() {
        assertDoesNotThrow(
                () -> {
                    String res = pc.decrypt(encStr, passPhrase);
                    assertEquals(str, res, "Decryption did not produce desired result");
                },
                "Decryption failed: ");
    }

    // -------------------------------------------------------------

    @Test
    void testDecorate() {
        String res = pc.decorate("aaa");
        assertEquals("{aaa}", res, "Decoration failed");
    }

    // -------------------------------------------------------------

    @Test
    void testUnDecorate() throws Exception {
        String res = pc.unDecorate("{aaa}");
        assertEquals("aaa", res, "Decoration failed");
    }

    // -------------------------------------------------------------

    @Test
    void testEncryptAndDecorate() throws Exception {
        String res = pc.encryptAndDecorate("my-password", "12345678");

        assertEquals('{', res.charAt(0));
    }
}
