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

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.EnumSet;

public class NativeLibraryLoader {
    static String libFileName = "libjssl.so";
    static String location = "/resources/native/";
    static volatile boolean loaded = false;

    public static synchronized void load() {
        if (loaded)
            return;

        Path tempPath = null;
        try {
            String tempDir = System.getProperty("java.io.tmpdir");
            if (tempDir == null || tempDir.isEmpty()) {
                tempDir = System.getProperty("user.home");
                if (tempDir == null || tempDir.isEmpty()) {
                    tempDir = System.getProperty("user.dir", ".");
                }
            }

            // PID + nanoTime + class identity: harder to predict than millis + threadId alone.
            // UUID.randomUUID() is avoided because it may depend on SecureRandom, which is not
            // yet available when this provider loads in a FIPS-compliant JDK.
            String uniqueSuffix = ProcessHandle.current().pid() + "-" +
                                  System.nanoTime() + "-" +
                                  System.identityHashCode(NativeLibraryLoader.class);
            tempPath = Paths.get(tempDir, "libjssl-" + uniqueSuffix + ".so");

            InputStream in = NativeLibraryLoader.class.getResourceAsStream(location + libFileName);
            if (in == null) {
                throw new IOException("Native library not found in resources: " + location + libFileName);
            }

            // CREATE_NEW maps to open(O_CREAT|O_EXCL): atomic creation that fails if the path
            // already exists or is a symlink, preventing pre-creation / symlink-substitution attacks.
            // POSIX permissions rwx------ ensure the file is never world-readable.
            try (FileChannel out = FileChannel.open(tempPath,
                     EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                     PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                 InputStream src = in) {
                byte[] buffer = new byte[8192];
                int bytesRead;
                while ((bytesRead = src.read(buffer)) != -1) {
                    ByteBuffer bb = ByteBuffer.wrap(buffer, 0, bytesRead);
                    while (bb.hasRemaining()) {
                        out.write(bb);
                    }
                }
            }

            System.load(tempPath.toAbsolutePath().toString());
            loaded = true;

        } catch (Exception e) {
            throw new RuntimeException("Failed to load native library " + libFileName + ": " + e.getMessage(), e);
        } finally {
            if (tempPath != null) {
                try {
                    Files.delete(tempPath);
                } catch (IOException ignored) {
                    // Non-critical: file will be cleaned up by OS temp cleanup
                }
            }
        }
    }
}
