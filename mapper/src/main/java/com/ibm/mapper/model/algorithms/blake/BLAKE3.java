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
package com.ibm.mapper.model.algorithms.blake;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.ClassicalBitSecurityLevel;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class BLAKE3 extends Algorithm implements MessageDigest, KeyDerivationFunction {
    // https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf

    private static final String NAME = "BLAKE3";

    public BLAKE3(int digestSize, @Nonnull DetectionLocation detectionLocation) {
        super(NAME, MessageDigest.class, detectionLocation);
        this.put(new DigestSize(digestSize, detectionLocation));
        this.put(new ClassicalBitSecurityLevel(128, detectionLocation));
    }

    public BLAKE3(@Nonnull DetectionLocation detectionLocation) {
        // 256-bit default output size
        this(256, detectionLocation);
    }

    public BLAKE3(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull BLAKE3 blake) {
        super(blake, asKind);
    }
}
