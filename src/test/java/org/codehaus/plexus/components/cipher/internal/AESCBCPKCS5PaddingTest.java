package org.codehaus.plexus.components.cipher.internal;

public class AESCBCPKCS5PaddingTest extends CipherTestSupport {
    @Override
    Cipher getCipher() {
        return new AESCBCPKCS5Padding();
    }
}
