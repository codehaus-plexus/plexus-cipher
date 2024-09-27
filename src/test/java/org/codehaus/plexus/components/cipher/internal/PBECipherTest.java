/*
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

package org.codehaus.plexus.components.cipher.internal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author Oleg Gusakov
 */
class PBECipherTest {
    PBECipher pbeCipher;

    final String clearText = "veryOpenText";

    final String encryptedText = "ce/l2ofOiSELRT1WAjOyNoZbG+2FQcrlOKEdDr5mi6esyR2LfvBY855yxW5bqHZi";

    final String password = "testtest";

    @BeforeEach
    void prepare() {
        pbeCipher = new PBECipher();
    }

    @Test
    void testEncrypt() throws Exception {
        String enc = pbeCipher.encrypt64(clearText, password);

        assertNotNull(enc);

        System.out.println(enc);

        String enc2 = pbeCipher.encrypt64(clearText, password);

        assertNotNull(enc2);

        System.out.println(enc2);

        assertNotEquals(enc, enc2);
    }

    @Test
    void testDecrypt() throws Exception {
        String clear = pbeCipher.decrypt64(encryptedText, password);

        assertEquals(clearText, clear);
    }

    @Test
    void testEncoding() throws Exception {
        System.out.println("file.encoding=" + System.getProperty("file.encoding"));

        String pwd = "äüöÜÖÄß\"§$%&/()=?é";
        String encPwd = pbeCipher.encrypt64(pwd, pwd);
        String decPwd = pbeCipher.decrypt64(encPwd, pwd);
        assertEquals(pwd, decPwd);
    }
}
