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

import java.util.Set;

/**
 * @author Oleg Gusakov
 */
public interface PlexusCipher {

    /**
     * Returns the available cipher algorithms, never {@code null}.
     */
    Set<String> availableCiphers();

    /**
     * Encrypt given string with the given alg and passPhrase and encode it into Base64 string.
     *
     * @param alg cipher alg to use, never {@code null}
     * @param str string to encrypt, never {@code null}
     * @param passPhrase pass phrase, never {@code null}
     * @return encrypted str, never {@code null}
     * @throws PlexusCipherException if encryption fails
     */
    String encrypt(String alg, String str, String passPhrase) throws PlexusCipherException;

    /**
     * Encrypt given string with the given alg and passPhrase and encode it into Base64 decorated string.
     *
     * @param alg cipher alg to use, never {@code null}
     * @param str string to encrypt, never {@code null}
     * @param passPhrase pass phrase, never {@code null}
     * @return encrypted and decorated str, never {@code null}
     * @throws PlexusCipherException if encryption fails
     */
    String encryptAndDecorate(String alg, String str, String passPhrase) throws PlexusCipherException;

    /**
     * Decrypt given Base64 encoded string with the given alg and passPhrase and return resulting string.
     *
     * @param alg cipher alg to use, never {@code null}
     * @param str string to encrypt, never {@code null}
     * @param passPhrase pass phrase, never {@code null}
     * @return encrypted and decorated str, never {@code null}
     * @throws PlexusCipherException if encryption fails
     */
    String decrypt(String alg, String str, String passPhrase) throws PlexusCipherException;

    /**
     * Decrypt given decorated  Base64 encoded string with the given alg and passPhrase and return resulting string.
     *
     * @param alg cipher alg to use, never {@code null}
     * @param str string to encrypt, never {@code null}
     * @param passPhrase pass phrase, never {@code null}
     * @return encrypted and decorated str, never {@code null}
     * @throws PlexusCipherException if encryption fails
     */
    String decryptDecorated(String alg, String str, String passPhrase) throws PlexusCipherException;

    /**
     * Check if given string is decorated.
     */
    boolean isEncryptedString(String str);

    /**
     * Remove decorations from string, if it was decorated.
     *
     * @throws PlexusCipherException is string is malformed
     */
    String unDecorate(String str) throws PlexusCipherException;

    /**
     * Decorates given string.
     */
    String decorate(String str);
}
