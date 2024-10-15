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
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.BlockCipherMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcBlockCipherMacTestFile {

    public static byte[] generateBlockCipherMac(byte[] key, byte[] input) { 
        AESEngine cipher = new AESEngine(); // Noncompliant {{(BlockCipher) AES}}
        int macSizeInBits = 128;

        BlockCipherMac mac =
                new BlockCipherMac(cipher, macSizeInBits); // Noncompliant {{(Mac) AES}}
        CipherParameters params = new KeyParameter(key);

        mac.init(params);

        mac.update(input, 0, input.length);

        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);

        return out;
    }
}
