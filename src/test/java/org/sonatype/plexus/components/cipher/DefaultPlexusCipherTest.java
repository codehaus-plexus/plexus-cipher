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
package org.sonatype.plexus.components.cipher;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Test the Plexus Cipher container
 *
 * @author Oleg Gusakov
 */
public class DefaultPlexusCipherTest {
    private final String passPhrase = "testtest";

    String str = "my testing phrase";

    String encStr = "LFulS0pAlmMHpDtm+81oPcqctcwpco5p4Fo7640/gqDRifCahXBefG4FxgKcu17v";

    DefaultPlexusCipher pc;

    // -------------------------------------------------------------
    @Before
    public void prepare() throws Exception {
        pc = new DefaultPlexusCipher();
    }

    @Test
    public void testIsEncryptedString() {
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
    public void testUnDecorate_BracesPermutations() throws PlexusCipherException {
        String noBraces = "This is a test";
        String normalBraces = "Comment {This is a test} other comment with a: }";
        String mixedBraces = "Comment {foo\\{This is a test\\}} other comment with a: }";

        assertEquals(noBraces, pc.unDecorate(normalBraces));

        assertEquals("foo\\{" + noBraces + "\\}", pc.unDecorate(mixedBraces));
    }

    // -------------------------------------------------------------

    @Test
    public void testDefaultAlgorithmExists() throws Exception {
        String[] res = DefaultPlexusCipher.getCryptoImpls("Cipher");
        assertNotNull("No Cipher providers found in the current environment", res);

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

    @Test
    public void stestFindDefaultAlgorithm() throws Exception {
        String[] res = DefaultPlexusCipher.getServiceTypes();
        assertNotNull("No service types found in the current environment", res);

        String[] impls = DefaultPlexusCipher.getCryptoImpls("Cipher");
        assertNotNull("No Cipher providers found in the current environment", impls);

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
    public void testEncrypt() throws Exception {
        String xRes = pc.encrypt(str, passPhrase);

        System.out.println(xRes);

        String res = pc.decrypt(xRes, passPhrase);

        assertEquals("Encryption/Decryption did not produce desired result", str, res);
    }

    // -------------------------------------------------------------

    @Test
    public void testEncryptVariableLengths() throws Exception {
        String xRes = null;
        String res = null;
        String pass = "g";

        for (int i = 0; i < 64; i++) {
            pass = pass + 'a';

            xRes = pc.encrypt(str, pass);

            System.out.println(pass.length() + ": " + xRes);

            res = pc.decrypt(xRes, pass);

            assertEquals("Encryption/Decryption did not produce desired result", str, res);
        }
    }

    // -------------------------------------------------------------
    public void testDecrypt() throws Exception {
        String res = pc.decrypt(encStr, passPhrase);
        assertEquals("Decryption did not produce desired result", str, res);
    }

    // -------------------------------------------------------------

    @Test
    public void testDecorate() throws Exception {
        String res = pc.decorate("aaa");
        assertEquals(
                "Decoration failed",
                PlexusCipher.ENCRYPTED_STRING_DECORATION_START + "aaa" + PlexusCipher.ENCRYPTED_STRING_DECORATION_STOP,
                res);
    }

    // -------------------------------------------------------------

    @Test
    public void testUnDecorate() throws Exception {
        String res = pc.unDecorate(
                PlexusCipher.ENCRYPTED_STRING_DECORATION_START + "aaa" + PlexusCipher.ENCRYPTED_STRING_DECORATION_STOP);
        assertEquals("Decoration failed", "aaa", res);
    }

    // -------------------------------------------------------------

    @Test
    public void testEncryptAndDecorate() throws Exception {
        String res = pc.encryptAndDecorate("my-password", "12345678");

        assertEquals('{', res.charAt(0));
    }
}
