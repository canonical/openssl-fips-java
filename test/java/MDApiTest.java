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
import java.nio.ByteBuffer;
import java.security.DigestException;
import java.util.Arrays;
import java.util.function.*;
import java.util.List;
import java.security.Security;
import java.security.MessageDigest;
import com.canonical.openssl.provider.OpenSSLFIPSProvider;

public class MDApiTest {

    private static byte[] input = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood.""".getBytes();

    private static byte[] input1 = """
       From that time on, the world was hers for the reading.
       She would never be lonely again, never miss the lack of intimate friends.
       Books became her friends and there was one for every mood""".getBytes();

    private static BiFunction<MessageDigest, byte[], byte[]> mdCompute = (md, input) -> {
        md.update(input, 0, input.length);
        return md.digest();
    };

    private static void runTest(String name) throws Exception {
        System.out.print("Testing " + name +  ": ");
        MessageDigest md1 = MessageDigest.getInstance(name, "OpenSSLFIPSProvider");
        MessageDigest md2 = MessageDigest.getInstance(name, "OpenSSLFIPSProvider");
        MessageDigest md3 = MessageDigest.getInstance(name, "OpenSSLFIPSProvider");
        byte[] output1 = mdCompute.apply(md1, input);
        byte[] output2 = mdCompute.apply(md2, input);
        byte[] output3 = mdCompute.apply(md3, input1);
        if (Arrays.equals(output1, output2) && !Arrays.equals(output2, output3)) {
            System.out.println("PASSED");
        } else {
            System.out.println("FAILED");
        }
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new OpenSSLFIPSProvider());
        List<String> tests = List.of("MDSHA1", "MDSHA224", "MDSHA3_384", "MDSHA3_512");
        for (var test: tests) {
            runTest(test);
        }
    }
}
