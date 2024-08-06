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
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;

public final class ChaCha20 extends Algorithm implements StreamCipher {
    private static final String NAME = "ChaCha20";

    public ChaCha20(@NotNull DetectionLocation detectionLocation) {
        super(NAME, StreamCipher.class, detectionLocation);
    }

    public ChaCha20(int keyLength, @NotNull DetectionLocation detectionLocation) {
        super(NAME, StreamCipher.class, detectionLocation);
        this.append(new KeyLength(keyLength, detectionLocation));
    }

    public ChaCha20(
            int keyLength, @Nonnull Padding padding, @NotNull DetectionLocation detectionLocation) {
        super(NAME, StreamCipher.class, detectionLocation);
        this.append(new KeyLength(keyLength, detectionLocation));
        this.append(padding);
    }

    public ChaCha20(@Nonnull final Class<? extends Cipher> asKind, @NotNull ChaCha20 chaCha20) {
        super(chaCha20, asKind);
    }
}
