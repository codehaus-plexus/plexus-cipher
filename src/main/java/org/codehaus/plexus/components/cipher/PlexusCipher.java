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
package org.codehaus.plexus.components.cipher;

/**
 * @author Oleg Gusakov
 */
public interface PlexusCipher {
    String ENCRYPTED_STRING_DECORATION_START = "{";

    String ENCRYPTED_STRING_DECORATION_STOP = "}";

    /**
     * encrypt given string with the given passPhrase and encode it into base64
     *
     * @param str       string to encrypt
     * @param passPhrase pass phrase
     * @return encrypted str
     * @throws PlexusCipherException if encryption fails
     */
    String encrypt(String str, String passPhrase) throws PlexusCipherException;

    /**
     * encrypt given string with the given passPhrase, encode it into base64 and return result, wrapped into { }
     * decorations
     *
     * @param str      string to encrypt
     * @param passPhrase pass phrase
     * @return encrypted and decorated str
     * @throws PlexusCipherException if encryption fails
     */
    String encryptAndDecorate(String str, String passPhrase) throws PlexusCipherException;

    /**
     * decrypt given base64 encrypted string
     *
     * @param str       base64 encoded string
     * @param passPhrase     pass phrase
     * @return decrypted str
     * @throws PlexusCipherException if decryption fails
     */
    String decrypt(String str, String passPhrase) throws PlexusCipherException;

    /**
     * decrypt given base64 encoded encrypted string. If string is decorated, decrypt base64 encoded string inside
     * decorations
     *
     * @param str    base64 encoded string
     * @param passPhrase     pass phrase
     * @return decrypted decorated str
     * @throws PlexusCipherException if decryption fails
     */
    String decryptDecorated(String str, String passPhrase) throws PlexusCipherException;

    /**
     * check if given string is decorated
     *
     * @param str string to check
     * @return true if string is encrypted
     */
    boolean isEncryptedString(String str);

    /**
     * return string inside decorations
     *
     * @param str decorated string
     * @return undecorated str
     * @throws PlexusCipherException if decryption fails
     */
    String unDecorate(String str) throws PlexusCipherException;

    /**
     * decorated given string with { and }
     *
     * @param str string to decorate
     * @return decorated str
     */
    String decorate(String str);
}
