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
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;

public final class SM4 extends Algorithm implements BlockCipher {
    private static final String NAME = "SM4"; // SMS4

    public SM4(@NotNull DetectionLocation detectionLocation) {
        super(NAME, BlockCipher.class, detectionLocation);
    }

    public SM4(@Nonnull Mode mode, @NotNull DetectionLocation detectionLocation) {
        super(NAME, BlockCipher.class, detectionLocation);
        this.append(mode);
    }

    public SM4(@Nonnull final Class<? extends IPrimitive> asKind, @NotNull SM4 sm4) {
        super(sm4, asKind);
    }
}
