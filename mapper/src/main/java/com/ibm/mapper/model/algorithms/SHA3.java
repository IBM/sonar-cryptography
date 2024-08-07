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
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public final class SHA3 extends Algorithm implements MessageDigest {
    private static final String NAME = "SHA3";

    public SHA3(int digestSize, @Nonnull DetectionLocation detectionLocation) {
        super(NAME + "-" + digestSize, MessageDigest.class, detectionLocation);
        this.append(new DigestSize(digestSize, detectionLocation));
    }

    public SHA3(
            int digestSize,
            @Nonnull MessageDigest preHash,
            @Nonnull DetectionLocation detectionLocation) {
        super(NAME + "-" + digestSize, MessageDigest.class, detectionLocation);
        this.append(new DigestSize(digestSize, detectionLocation));
        this.append(preHash);
    }

    public SHA3(
            int digestSize,
            @Nonnull final Class<? extends IPrimitive> asKind,
            @Nonnull DetectionLocation detectionLocation) {
        super(NAME + "-" + digestSize, asKind, detectionLocation);
    }

    public SHA3(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull SHA3 sha3) {
        super(sha3, asKind);
    }
}
