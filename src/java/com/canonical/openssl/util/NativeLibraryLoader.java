package com.canonical.openssl.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;

public class NativeLibraryLoader {
    static String libFileName = "libjssl.so";
    static String location = "/resources/native/";
    static boolean loaded = false;

    public static synchronized void load() {
        if (loaded)
            return;

        try {
            InputStream in = NativeLibraryLoader.class.getResourceAsStream(location + libFileName);

            File tempFile = Files.createTempFile(libFileName, "").toFile();
            tempFile.deleteOnExit();

            try (FileOutputStream out = new FileOutputStream(tempFile)) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
            System.load(tempFile.getAbsolutePath());
            loaded = true;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load native libary " + libFileName + ": " + e);
        }
    }
}
