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
import org.bouncycastle.crypto.macs.GOST28147Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.encoders.Hex;

public class BcGOST28147MacTestFile {
    public static void main(String[] args) {
        try {
            byte[] key = Hex.decode("0123456789abcdef0123456789abcdef");
            byte[] input = "Hello, BouncyCastle!".getBytes();

            GOST28147Mac mac = new GOST28147Mac(); // Noncompliant {{(Mac) GOST28147}}
            CipherParameters params = new ParametersWithIV(new KeyParameter(key), new byte[10]);
            mac.init(params);

            mac.update(input, 0, input.length);
            byte[] output = new byte[mac.getMacSize()];
            mac.doFinal(output, 0);

            System.out.println("MAC: " + Hex.toHexString(output));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
