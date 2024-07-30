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
package com.ibm.mapper.mapper.ssl;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class EncryptionAlgorithmMapper implements IMapper {

    @NotNull @Override
    public Optional<Cipher> parse(
            @Nullable String str, @NotNull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str) {
            case "AES 128 CCM 8" ->
                    Optional.of(new AES(128, new CCM(8, detectionLocation), detectionLocation));
            case "AES 128 CCM" ->
                    Optional.of(new AES(128, new CCM(detectionLocation), detectionLocation));
            case "AES 128 GCM" ->
                    Optional.of(new AES(128, new GCM(detectionLocation), detectionLocation));
            default -> Optional.empty();
        };
    }
}
