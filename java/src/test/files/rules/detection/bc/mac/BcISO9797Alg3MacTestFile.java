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

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

public class BcISO9797Alg3MacTestFile {

    public static byte[] calculateMac(byte[] key, byte[] iv, byte[] data) {
        BlockCipher cipher = new AESEngine(); // Noncompliant {{(BlockCipher) AES}}
        ISO9797Alg3Mac mac = new ISO9797Alg3Mac(cipher, 64, new ISO7816d4Padding());
        // Noncompliant@-1 {{(Mac) AES}}

        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV keyParamWithIV = new ParametersWithIV(keyParam, iv);
        mac.init(keyParamWithIV);

        mac.update(data, 0, data.length);

        byte[] macResult = new byte[mac.getMacSize()];
        mac.doFinal(macResult, 0);

        return macResult;
    }
}
