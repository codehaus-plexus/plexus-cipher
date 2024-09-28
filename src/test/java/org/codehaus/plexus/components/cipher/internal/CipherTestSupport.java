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

import java.nio.charset.Charset;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

public abstract class CipherTestSupport {
    final String clearText = "veryOpenText";
    final String password = "testtest";

    Cipher pbeCipher;

    @BeforeEach
    void prepare() {
        pbeCipher = getCipher();
    }

    abstract Cipher getCipher();

    @Test
    void testEncrypt() throws Exception {
        String enc = pbeCipher.encrypt(clearText, password);
        assertNotNull(enc);
        System.out.println(enc);
        String enc2 = pbeCipher.encrypt(clearText, password);
        assertNotNull(enc2);
        System.out.println(enc2);
        assertNotEquals(enc, enc2);
    }

    @Test
    void testDecrypt() throws Exception {
        String enc = pbeCipher.encrypt(clearText, password);
        String clear = pbeCipher.decrypt(enc, password);
        assertEquals(clearText, clear);
    }

    @Test
    void testEncoding() throws Exception {
        System.out.println("file.encoding=" + Charset.defaultCharset().displayName());
        String pwd = "äüöÜÖÄß\"§$%&/()=?é";
        String encPwd = pbeCipher.encrypt(pwd, pwd);
        String decPwd = pbeCipher.decrypt(encPwd, pwd);
        assertEquals(pwd, decPwd);
    }
}
