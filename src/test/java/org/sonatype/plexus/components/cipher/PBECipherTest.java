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

package org.sonatype.plexus.components.cipher;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

/**
 * @author Oleg Gusakov
 */
public class PBECipherTest
{
    PBECipher _cipher;

    String _cleatText = "veryOpenText";

    String _encryptedText = "F7eMV2QRQF4H0ODCA1nrTGUWacCXVvPemSjaQjGbO6U=";

    String _password = "testtest";

    @Before
    public void prepare()
        throws Exception
    {
        _cipher = new PBECipher();
    }

    @Test
    public void testEncrypt()
        throws Exception
    {
        String enc = _cipher.encrypt64( _cleatText, _password );

        assertNotNull( enc );

        System.out.println( enc );

        String enc2 = _cipher.encrypt64( _cleatText, _password );

        assertNotNull( enc2 );

        System.out.println( enc2 );

        assertFalse( enc.equals( enc2 ) );
    }

    @Test
    public void testDecrypt()
        throws Exception
    {
        String clear = _cipher.decrypt64( _encryptedText, _password );

        assertEquals( _cleatText, clear );
    }

    @Test
    public void testEncoding()
    	throws Exception
    {
    	System.out.println("file.encoding=" + System.getProperty("file.encoding"));
    	
    	String pwd = "äüöÜÖÄß\"§$%&/()=?é";
    	String encPwd = _cipher.encrypt64(pwd, pwd);
    	String decPwd = _cipher.decrypt64(encPwd, pwd);
    	assertEquals(pwd, decPwd);
    }
}
