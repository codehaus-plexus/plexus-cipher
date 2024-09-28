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

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.codehaus.plexus.components.cipher.PlexusCipher;
import org.codehaus.plexus.components.cipher.PlexusCipherException;

import static java.util.Objects.requireNonNull;

/**
 * Default implementation of {@link PlexusCipher}. This class is thread safe.
 *
 * @author Oleg Gusakov
 */
@Singleton
@Named
public class DefaultPlexusCipher implements PlexusCipher {
    private static final Pattern ENCRYPTED_STRING_PATTERN = Pattern.compile(".*?[^\\\\]?\\{(.*?[^\\\\])}.*");
    private static final String ENCRYPTED_STRING_DECORATION_START = "{";
    private static final String ENCRYPTED_STRING_DECORATION_STOP = "}";

    private final Map<String, Cipher> ciphers;

    @Inject
    public DefaultPlexusCipher(Map<String, Cipher> ciphers) {
        this.ciphers = requireNonNull(ciphers);
    }

    @Override
    public Set<String> availableCiphers() {
        return Collections.unmodifiableSet(ciphers.keySet());
    }

    @Override
    public String encrypt(String alg, String str, String passPhrase) throws PlexusCipherException {
        requireNonNull(alg);
        requireNonNull(str);
        requireNonNull(passPhrase);
        if (str.isEmpty()) {
            return str;
        }
        return requireCipher(alg).encrypt(str, passPhrase);
    }

    @Override
    public String encryptAndDecorate(String alg, String str, String passPhrase) throws PlexusCipherException {
        return decorate(encrypt(alg, str, passPhrase));
    }

    @Override
    public String decrypt(String alg, String str, String passPhrase) throws PlexusCipherException {
        requireNonNull(alg);
        requireNonNull(str);
        requireNonNull(passPhrase);
        if (str.isEmpty()) {
            return str;
        }
        return requireCipher(alg).decrypt(str, passPhrase);
    }

    @Override
    public String decryptDecorated(String alg, String str, String passPhrase) throws PlexusCipherException {
        requireNonNull(alg);
        requireNonNull(str);
        requireNonNull(passPhrase);
        if (str.isEmpty()) {
            return str;
        }
        if (isEncryptedString(str)) {
            str = unDecorate(str);
        }
        return decrypt(alg, str, passPhrase);
    }

    @Override
    public boolean isEncryptedString(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        Matcher matcher = ENCRYPTED_STRING_PATTERN.matcher(str);
        return matcher.matches() || matcher.find();
    }

    @Override
    public String unDecorate(String str) throws PlexusCipherException {
        requireNonNull(str);
        Matcher matcher = ENCRYPTED_STRING_PATTERN.matcher(str);
        if (matcher.matches() || matcher.find()) {
            return matcher.group(1);
        } else {
            throw new PlexusCipherException("Malformed decorated string");
        }
    }

    @Override
    public String decorate(String str) {
        return ENCRYPTED_STRING_DECORATION_START + (str == null ? "" : str) + ENCRYPTED_STRING_DECORATION_STOP;
    }

    private Cipher requireCipher(String alg) throws PlexusCipherException {
        Cipher cipher = ciphers.get(alg);
        if (cipher == null) {
            throw new PlexusCipherException("Unsupported alg: " + alg);
        }
        return cipher;
    }

    // ---------------------------------------------------------------

    /**
     * Exploratory part. This method returns all available services types
     */
    public static String[] getServiceTypes() {
        Set<String> result = new HashSet<>();

        // All providers
        for (Provider provider : Security.getProviders()) {
            // Get services provided by each provider
            Set<Object> keys = provider.keySet();
            for (Object o : keys) {
                String key = (String) o;
                key = key.split(" ")[0];

                if (key.startsWith("Alg.Alias.")) {
                    // Strip the alias
                    key = key.substring(10);
                }
                int ix = key.indexOf('.');
                result.add(key.substring(0, ix));
            }
        }
        return result.toArray(new String[0]);
    }

    /**
     * This method returns the available implementations for a service type
     */
    public static String[] getCryptoImpls(final String serviceType) {
        Set<String> result = new HashSet<>();

        // All providers
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            // Get services provided by each provider
            Set<Object> keys = provider.keySet();
            for (Object o : keys) {
                String key = (String) o;
                key = key.split(" ")[0];

                if (key.startsWith(serviceType + ".")) {
                    result.add(key.substring(serviceType.length() + 1));
                } else if (key.startsWith("Alg.Alias." + serviceType + ".")) {
                    // This is an alias
                    result.add(key.substring(serviceType.length() + 11));
                }
            }
        }
        return result.toArray(new String[0]);
    }

    public static void main(final String[] args) {
        String[] serviceTypes = getServiceTypes();
        for (String serviceType : serviceTypes) {
            System.out.println(serviceType + ": provider list");
            for (String provider : getCryptoImpls(serviceType)) {
                System.out.println("        " + provider);
            }
        }
    }
}
