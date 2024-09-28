package org.codehaus.plexus.components.cipher.internal;

public class AESGCMNoPaddingTest extends CipherTestSupport {
    @Override
    Cipher getCipher() {
        return new AESGCMNoPadding();
    }
}
