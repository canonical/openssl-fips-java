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
import java.nio.file.Files;
import java.nio.file.Paths;

public class NativeLibraryLoader {
    static String libFileName = "libjssl.so";
    static String location = "/resources/native/";
    static boolean loaded = false;

    public static synchronized void load() {
        if (loaded)
            return;

        try {
            InputStream in = NativeLibraryLoader.class.getResourceAsStream(location + libFileName);

            File tempFile = Files.createFile(Paths.get("/tmp/" + libFileName)).toFile();

            try (FileOutputStream out = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }

            System.load(tempFile.getAbsolutePath());
            loaded = true;

            tempFile.delete();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load native libary " + libFileName + ": " + e);
        }
    }
}
