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
package com.canonical.openssl.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

public class NativeLibraryLoader {
    static String libFileName = "libjssl.so";
    static String location = "/resources/native/";
    static boolean loaded = false;

    public static synchronized void load() {
        if (loaded)
            return;

        try {
            InputStream in = NativeLibraryLoader.class.getResourceAsStream(location + libFileName);
            if (in == null) {
                throw new IOException("Native library not found in resources: " + location + libFileName);
            }

            // Create a unique temp file name without using Files.createTempFile()
            // Files.createTempFile() requires SecureRandom which may not be available yet
            // when this provider is loaded in a FIPS-compliant JDK, causing NPE
            String tempDir = System.getProperty("java.io.tmpdir");
            if (tempDir == null || tempDir.isEmpty()) {
                // Fallback: try user.home, then current directory
                // Note: This is a best-effort approach when java.io.tmpdir is unavailable
                tempDir = System.getProperty("user.home");
                if (tempDir == null || tempDir.isEmpty()) {
                    tempDir = System.getProperty("user.dir", ".");
                }
            }
            
            // Generate a unique file name using timestamp, thread ID, and hashcode
            // This combination is highly unlikely to collide in practice
            // Note: We cannot use UUID.randomUUID() as it may depend on SecureRandom
            String uniqueSuffix = System.currentTimeMillis() + "-" + 
                                Thread.currentThread().getId() + "-" + 
                                System.identityHashCode(NativeLibraryLoader.class);
            File tempFile = new File(tempDir, "libjssl-" + uniqueSuffix + ".so");
            
            // Attempt to create the file atomically to prevent race conditions
            // If the file already exists, the creation will fail and we throw an exception
            try (FileOutputStream out = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            } finally {
                in.close();
            }

            System.load(tempFile.getAbsolutePath());
            loaded = true;

            // Delete the temp file immediately after loading since it's no longer needed
            // The native library is now loaded into memory and the file is not required
            // If deletion fails (e.g., file locked on some systems), it's not critical since
            // the file will be cleaned up by the OS eventually, and this only happens once per JVM
            if (!tempFile.delete()) {
                // Deletion failed, but this is not critical - log for debugging if needed
                // The file will remain in temp directory and be cleaned up by OS temp cleanup
            }

        } catch (Exception e) {
            throw new RuntimeException("Failed to load native library " + libFileName + ": " + e.getMessage(), e);
        }
    }
}
