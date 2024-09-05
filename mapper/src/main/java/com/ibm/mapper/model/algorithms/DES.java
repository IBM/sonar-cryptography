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
import com.ibm.mapper.model.ClassicalBitSecurityLevel;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;

public final class DES extends Algorithm implements BlockCipher {
    // https://en.wikipedia.org/wiki/Data_Encryption_Standard

    private static final String NAME = "DES";

    @Override
    public @NotNull String asString() {
        final StringBuilder sb = new StringBuilder(this.name);
        this.hasChildOfType(KeyLength.class).ifPresent(k -> sb.append(k.asString()));
        this.hasChildOfType(Mode.class).ifPresent(m -> sb.append("-").append(m.asString()));
        this.hasChildOfType(Padding.class).ifPresent(p -> sb.append("-").append(p.asString()));
        return sb.toString();
    }

    public DES(@NotNull DetectionLocation detectionLocation) {
        super(NAME, BlockCipher.class, detectionLocation);
        this.put(new KeyLength(56, detectionLocation));
        this.put(new BlockSize(64, detectionLocation));
        this.put(new ClassicalBitSecurityLevel(56, detectionLocation));
    }

    public DES(int keyLength, @NotNull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(new BlockSize(64, detectionLocation));
    }

    public DES(int keyLength, @Nonnull Mode mode, @NotNull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(mode);
        this.put(new BlockSize(64, detectionLocation));
    }

    public DES(
            int keyLength,
            @Nonnull Mode mode,
            @Nonnull Padding padding,
            @NotNull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(mode);
        this.put(padding);
        this.put(new BlockSize(64, detectionLocation));
    }

    public DES(@Nonnull Mode mode, @NotNull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(mode);
        this.put(new BlockSize(64, detectionLocation));
    }

    public DES(
            @Nonnull Mode mode,
            @Nonnull Padding padding,
            @NotNull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(mode);
        this.put(padding);
        this.put(new BlockSize(64, detectionLocation));
    }

    public DES(@Nonnull final Class<? extends IPrimitive> asKind, @NotNull DES des) {
        super(des, asKind);
    }
}
