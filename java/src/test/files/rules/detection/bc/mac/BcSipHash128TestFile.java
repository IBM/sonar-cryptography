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

import org.bouncycastle.crypto.macs.SipHash;
import org.bouncycastle.crypto.macs.SipHash128;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcSipHash128TestFile {
    public static long sipHash(byte[] data, byte[] key) {
        SipHash sipHash = new SipHash(); // Noncompliant {{SipHash}}
        sipHash.init(new KeyParameter(key));
        sipHash.update(data, 0, data.length);
        return sipHash.doFinal();
    }

    public static long sipHash128(byte[] data, byte[] key) {
        SipHash128 sipHash = new SipHash128(); // Noncompliant {{SipHash128}}
        sipHash.init(new KeyParameter(key));
        sipHash.update(data, 0, data.length);
        return sipHash.doFinal();
    }
}
