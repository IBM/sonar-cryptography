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

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.macs.Blake3Mac;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcBlake3MacTestFile {

    public static byte[] generateBlake3Mac(byte[] key, byte[] message) {
        Blake3Digest blake3Digest = new Blake3Digest();
        KeyParameter keyParameter = new KeyParameter(key);

        Mac blake3Mac = new Blake3Mac(blake3Digest); // Noncompliant {{(Mac) BLAKE3}}
        blake3Mac.init(keyParameter);

        blake3Mac.update(message, 0, message.length);
        byte[] output = new byte[blake3Mac.getMacSize()];
        blake3Mac.doFinal(output, 0);

        return output;
    }
}
