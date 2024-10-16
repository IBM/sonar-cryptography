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
import org.bouncycastle.crypto.macs.SkeinMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class BcSkeinMacTestFile {

    public static void useSkeinMac() {
        // Initialize SkeinMac with state size and digest size
        int stateSizeBits = 128; // Example state size
        int digestSizeBits = 256; // Example digest size
        Mac skeinMac = new SkeinMac(stateSizeBits, digestSizeBits); // Noncompliant {{(Mac) Skein}}

        // Provide input data
        byte[] data = "Hello, Bouncy Castle!".getBytes();

        // Initialize the SkeinMac with a key
        byte[] key = "ThisIsASecretKey".getBytes();
        skeinMac.init(new KeyParameter(key));

        // Update the MAC with the data
        skeinMac.update(data, 0, data.length);

        // Calculate the MAC
        byte[] mac = new byte[skeinMac.getMacSize()];
        skeinMac.doFinal(mac, 0);

        // Print the MAC in hexadecimal format
        System.out.println("SkeinMac: " + Hex.toHexString(mac));
    }
}
