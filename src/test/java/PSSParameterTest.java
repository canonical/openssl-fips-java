/*
 * Copyright (C) Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

import java.security.AlgorithmParameters;
import java.security.Security;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import java.security.InvalidAlgorithmParameterException;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class PSSParameterTest {

    @BeforeClass
    public static void addProvider() {
        Security.addProvider(new OpenSSLFIPSProvider());
    }

    @Test
    public void testExplicitPSSParametersRoundTrip() throws Exception {
        Signature sig = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");

        PSSParameterSpec original = new PSSParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
        sig.setParameter(original);

        AlgorithmParameters ap = sig.getParameters();
        assertNotNull("getParameters() must not return null after PSS params are set", ap);

        PSSParameterSpec returned = ap.getParameterSpec(PSSParameterSpec.class);
        assertEquals("digest algorithm", "SHA-256", returned.getDigestAlgorithm());
        assertEquals("MGF algorithm", "MGF1", returned.getMGFAlgorithm());
        assertEquals("salt length", 32, returned.getSaltLength());
        assertEquals("trailer field", 1, returned.getTrailerField());

        MGF1ParameterSpec mgf1 = (MGF1ParameterSpec) returned.getMGFParameters();
        assertNotNull("MGF1 parameters must not be null", mgf1);
        assertEquals("MGF1 digest", "SHA-256", mgf1.getDigestAlgorithm());
    }

    @Test
    public void testMGF1DigestDefaultsToMessageDigest() throws Exception {
        Signature sig = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");

        // PSSParameterSpec(int) leaves MGFParameters null; mgf1Digest must fall
        // back to the message digest ("SHA-1") inside engineGetParameters().
        sig.setParameter(new PSSParameterSpec(20));

        AlgorithmParameters ap = sig.getParameters();
        assertNotNull("getParameters() must not return null after PSS params are set", ap);

        PSSParameterSpec returned = ap.getParameterSpec(PSSParameterSpec.class);
        assertEquals("message digest", "SHA-1", returned.getDigestAlgorithm());

        MGF1ParameterSpec mgf1 = (MGF1ParameterSpec) returned.getMGFParameters();
        assertNotNull("MGF1 parameters must not be null", mgf1);
        assertEquals("MGF1 digest must default to message digest", "SHA-1", mgf1.getDigestAlgorithm());
    }

    @Test
    public void testRejectsNonMGF1Algorithm() throws Exception {
        Signature sig = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        try {
            sig.setParameter(new PSSParameterSpec(
                    "SHA-256", "SHAKE128", MGF1ParameterSpec.SHA256, 32, 1));
            fail("Expected InvalidAlgorithmParameterException for non-MGF1 MGF");
        } catch (InvalidAlgorithmParameterException expected) {
            // correct
        }
    }

    @Test
    public void testRejectsNonOneTrailerField() throws Exception {
        Signature sig = Signature.getInstance("RSAwithSHA256", "OpenSSLFIPSProvider");
        try {
            sig.setParameter(new PSSParameterSpec(
                    "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 2));
            fail("Expected InvalidAlgorithmParameterException for trailerField != 1");
        } catch (InvalidAlgorithmParameterException expected) {
            // correct
        }
    }
}
