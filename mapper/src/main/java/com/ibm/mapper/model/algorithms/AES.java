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
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;

public final class AES extends Algorithm implements BlockCipher, AuthenticatedEncryption {
    private static final String NAME = "AES"; // Rijndael

    @Override
    public @NotNull String asString() {
        final StringBuilder sb = new StringBuilder(this.name);
        this.hasChildOfType(KeyLength.class).ifPresent(k -> sb.append(k.asString()));
        this.hasChildOfType(Mode.class).ifPresent(m -> sb.append("-").append(m.asString()));
        this.hasChildOfType(Padding.class).ifPresent(p -> sb.append("-").append(p.asString()));
        return sb.toString();
    }

    public AES(@NotNull DetectionLocation detectionLocation) {
        this(BlockCipher.class, detectionLocation);
    }

    public AES(int keyLength, @NotNull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(new BlockSize(128, detectionLocation));
    }

    public AES(@Nonnull Mode mode, @NotNull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new BlockSize(128, detectionLocation));
        this.put(mode);
    }

    public AES(int keyLength, @Nonnull Mode mode, @NotNull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(new BlockSize(128, detectionLocation));
        this.put(mode);
    }

    public AES(
            int keyLength,
            @Nonnull Mode mode,
            @Nonnull Padding padding,
            @NotNull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new KeyLength(keyLength, detectionLocation));
        this.put(new BlockSize(128, detectionLocation));
        this.put(mode);
        this.put(padding);
    }

    public AES(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull AES aes) {
        super(aes, asKind);
    }

    public AES(
            @Nonnull final Class<? extends IPrimitive> asKind,
            @NotNull DetectionLocation detectionLocation) {
        super(NAME, asKind, detectionLocation);
        this.put(new BlockSize(128, detectionLocation));
    }
}
