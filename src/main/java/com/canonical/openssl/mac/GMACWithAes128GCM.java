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
package com.canonical.openssl.mac;

public final class GMACWithAes128GCM extends OpenSSLMAC {
    protected String getAlgorithm() {
        return "GMAC";
    }

    protected String getCipherType() {
        return "AES-128-GCM";
    }

    protected String getDigestType() {
        return null;
    }

    // TODO: a random IV?
    protected byte[] getIV() {
        return new byte[] { (byte)0xe0, (byte)0xe0, (byte)0x0f, (byte)0x19,
                            (byte)0xfe, (byte)0xd7, (byte)0xba, (byte)0x01,
                            (byte)0x36, (byte)0xa7, (byte)0x97, (byte)0xf3 };
    }
}
