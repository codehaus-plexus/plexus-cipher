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

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Named;
import javax.inject.Singleton;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

import org.codehaus.plexus.components.cipher.PlexusCipherException;

@Singleton
@Named(AESGCMNoPadding.CIPHER_ALG)
public class AESGCMNoPadding implements org.codehaus.plexus.components.cipher.internal.Cipher {
    public static final String CIPHER_ALG = "AES/GCM/NoPadding";

    private static final int SPICE_SIZE = 16;
    private static final int SALT_SIZE = 8;
    private static final int CHUNK_SIZE = 16;
    private static final String KEY_ALG = "AES";
    private static final int PBE_ITERATIONS = 310000;
    private static final SecureRandom _secureRandom = new SecureRandom();

    private byte[] getSalt(int sz) {
        byte[] res = new byte[sz];
        _secureRandom.nextBytes(res);
        return res;
    }

    @Override
    public String encrypt(String clearText, String password) throws PlexusCipherException {
        try {
            byte[] clearBytes = clearText.getBytes(StandardCharsets.UTF_8);
            byte[] salt = getSalt(SALT_SIZE);
            Cipher cipher = createCipher(password.toCharArray(), salt, Cipher.ENCRYPT_MODE);
            byte[] encryptedBytes = cipher.doFinal(clearBytes);
            int len = encryptedBytes.length;
            byte padLen = (byte) (CHUNK_SIZE - (SALT_SIZE + len + 1) % CHUNK_SIZE);
            int totalLen = SALT_SIZE + len + padLen + 1;
            byte[] allEncryptedBytes = getSalt(totalLen);
            System.arraycopy(salt, 0, allEncryptedBytes, 0, SALT_SIZE);
            allEncryptedBytes[SALT_SIZE] = padLen;
            System.arraycopy(encryptedBytes, 0, allEncryptedBytes, SALT_SIZE + 1, len);
            return Base64.getEncoder().encodeToString(allEncryptedBytes);
        } catch (Exception e) {
            throw new PlexusCipherException(e.getMessage(), e);
        }
    }

    @Override
    public String decrypt(String encryptedText, String password) throws PlexusCipherException {
        try {
            byte[] allEncryptedBytes = Base64.getDecoder().decode(encryptedText.getBytes());
            int totalLen = allEncryptedBytes.length;
            byte[] salt = new byte[SALT_SIZE];
            System.arraycopy(allEncryptedBytes, 0, salt, 0, SALT_SIZE);
            byte padLen = allEncryptedBytes[SALT_SIZE];
            byte[] encryptedBytes = new byte[totalLen - SALT_SIZE - 1 - padLen];
            System.arraycopy(allEncryptedBytes, SALT_SIZE + 1, encryptedBytes, 0, encryptedBytes.length);
            Cipher cipher = createCipher(password.toCharArray(), salt, Cipher.DECRYPT_MODE);
            byte[] clearBytes = cipher.doFinal(encryptedBytes);
            return new String(clearBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new PlexusCipherException(e.getMessage(), e);
        }
    }

    private Cipher createCipher(char[] pwd, byte[] salt, int mode)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
                    InvalidAlgorithmParameterException, InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(pwd, salt, PBE_ITERATIONS, SPICE_SIZE * 16);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        byte[] keyAndIv = factory.generateSecret(spec).getEncoded();
        byte[] key = new byte[SPICE_SIZE];
        byte[] iv = new byte[12];
        _secureRandom.nextBytes(iv);
        System.arraycopy(keyAndIv, 0, key, 0, key.length);
        Cipher cipher = Cipher.getInstance(CIPHER_ALG);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(mode, new SecretKeySpec(key, KEY_ALG), gcmSpec);
        return cipher;
    }
}
