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

import javax.inject.Named;
import javax.inject.Singleton;

import java.security.Provider;
import java.security.Security;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Default implementation of {@link PlexusCipher}. This class is thread safe.
 *
 * @author Oleg Gusakov
 */
@Singleton
@Named
public class DefaultPlexusCipher implements PlexusCipher {
    private static final Pattern ENCRYPTED_STRING_PATTERN = Pattern.compile(".*?[^\\\\]?\\{(.*?[^\\\\])\\}.*");

    private final PBECipher _cipher;

    // ---------------------------------------------------------------
    public DefaultPlexusCipher() {
        _cipher = new PBECipher();
    }

    // ---------------------------------------------------------------
    @Override
    public String encrypt(final String str, final String passPhrase) throws PlexusCipherException {
        if (str == null || str.isEmpty()) {
            return str;
        }

        return _cipher.encrypt64(str, passPhrase);
    }

    // ---------------------------------------------------------------
    @Override
    public String encryptAndDecorate(final String str, final String passPhrase) throws PlexusCipherException {
        return decorate(encrypt(str, passPhrase));
    }

    // ---------------------------------------------------------------
    @Override
    public String decrypt(final String str, final String passPhrase) throws PlexusCipherException {
        if (str == null || str.isEmpty()) {
            return str;
        }

        return _cipher.decrypt64(str, passPhrase);
    }

    // ---------------------------------------------------------------
    @Override
    public String decryptDecorated(final String str, final String passPhrase) throws PlexusCipherException {
        if (str == null || str.isEmpty()) {
            return str;
        }

        if (isEncryptedString(str)) {
            return decrypt(unDecorate(str), passPhrase);
        }

        return decrypt(str, passPhrase);
    }

    // ----------------------------------------------------------------------------
    @Override
    public boolean isEncryptedString(final String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }

        Matcher matcher = ENCRYPTED_STRING_PATTERN.matcher(str);

        return matcher.matches() || matcher.find();
    }

    // ----------------------------------------------------------------------------
    @Override
    public String unDecorate(final String str) throws PlexusCipherException {
        Matcher matcher = ENCRYPTED_STRING_PATTERN.matcher(str);
        if (matcher.matches() || matcher.find()) {
            return matcher.group(1);
        } else {
            throw new PlexusCipherException("Malformed decorated string");
        }
    }

    // ----------------------------------------------------------------------------
    @Override
    public String decorate(final String str) {
        return ENCRYPTED_STRING_DECORATION_START + (str == null ? "" : str) + ENCRYPTED_STRING_DECORATION_STOP;
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

    // ---------------------------------------------------------------
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
