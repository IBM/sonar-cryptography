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
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public class Kalyna extends Algorithm implements BlockCipher {
    // https://en.wikipedia.org/wiki/Kalyna_(cipher)

    private static final String NAME = "Kalyna"; // DSTU 7624:2014

    public Kalyna(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, BlockCipher.class, detectionLocation);
    }

    private Kalyna(@Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        super(name, BlockCipher.class, detectionLocation);
    }

    public Kalyna(int blockSize, @Nonnull DetectionLocation detectionLocation) {
        this(NAME + "-" + blockSize, detectionLocation);
        this.put(new BlockSize(blockSize, detectionLocation));
    }

    public Kalyna(int blockSize, int keyLength, @Nonnull DetectionLocation detectionLocation) {
        this(NAME + "-" + blockSize + "/" + keyLength, detectionLocation);
        this.put(new BlockSize(blockSize, detectionLocation));
        this.put(new KeyLength(keyLength, detectionLocation));
    }
}
