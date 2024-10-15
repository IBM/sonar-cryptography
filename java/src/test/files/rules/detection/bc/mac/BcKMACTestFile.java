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

import org.bouncycastle.crypto.macs.KMAC;

public class BcKMACTestFile {
    public static void kmacExample() {
        byte[] key = "secretkey".getBytes();
        byte[] data = "hello".getBytes();

        KMAC kmac = new KMAC(256, key); // Noncompliant {{(Mac) KMAC256}}

        kmac.update(data, 0, data.length);
        byte[] output = new byte[32]; // 256 bits = 32 bytes
        kmac.doFinal(output, 0);
        System.out.println("KMAC output: " + new String(output));
    }
}
