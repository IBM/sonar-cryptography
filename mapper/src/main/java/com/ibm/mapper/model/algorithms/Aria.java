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
import com.ibm.mapper.model.ICipher;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;

public final class Aria extends BlockCipher {
    private static final String NAME = "Aria";

    public Aria(@NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
    }

    public Aria(int keyLength, @NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(new KeyLength(keyLength, detectionLocation));
    }

    public Aria(int keyLength, @Nonnull Mode mode, @NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(new KeyLength(keyLength, detectionLocation));
        this.append(mode);
    }

    public Aria(
            int keyLength,
            @Nonnull Mode mode,
            @Nonnull Padding padding,
            @NotNull DetectionLocation detectionLocation) {
        super(new Algorithm(NAME, detectionLocation));
        this.append(new KeyLength(keyLength, detectionLocation));
        this.append(mode);
        this.append(padding);
    }

    public Aria(@Nonnull final Class<? extends ICipher> asKind, @NotNull Aria aria) {
        super(aria, asKind);
    }
}
