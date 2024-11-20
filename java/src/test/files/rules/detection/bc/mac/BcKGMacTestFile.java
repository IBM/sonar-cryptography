/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2024 IBM
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules.detection.bc.mac;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.engines.DSTU7624Engine;
import org.bouncycastle.crypto.macs.KGMac;
import org.bouncycastle.crypto.modes.KGCMBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class BcKGMacTestFile {
    public static void exampleGMAC() {
        byte[] key = Hex.decode("00112233445566778899AABBCCDDEEFF");
        byte[] input = Hex.decode("48656c6c6f20576f726c64"); // "Hello World" in hex

        DSTU7624Engine engine = new DSTU7624Engine(64); // Noncompliant {{(BlockCipher) Kalyna-64}}
        KGCMBlockCipher blockCipher = new KGCMBlockCipher(engine); // Noncompliant {{(AuthenticatedEncryption) Kalyna-64}}
        KGMac gmac = new KGMac(blockCipher, 128); // Noncompliant {{(Mac) Kalyna}}

        CipherParameters params = new KeyParameter(key);
        gmac.init(params);

        gmac.update(input, 0, input.length);
        byte[] outputMac = new byte[gmac.getMacSize()];
        gmac.doFinal(outputMac, 0);

        System.out.println(Hex.toHexString(outputMac)); // Output the MAC in hex
    }
}
