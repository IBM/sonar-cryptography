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
package com.ibm.mapper.mapper.jca;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaMessageDigestMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<MessageDigest> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "MD2" -> Optional.of(new MD2(detectionLocation));
            case "MD5" -> Optional.of(new MD5(detectionLocation));
            case "SHA", "SHA1", "SHA-1" -> Optional.of(new SHA(detectionLocation));
            case "SHA-224", "SHA224" -> Optional.of(new SHA2(224, detectionLocation));
            case "SHA-256", "SHA256" -> Optional.of(new SHA2(256, detectionLocation));
            case "SHA-384", "SHA384" -> Optional.of(new SHA2(384, detectionLocation));
            case "SHA-512", "SHA512" -> Optional.of(new SHA2(512, detectionLocation));
            case "SHA-512/224", "SHA512/224" ->
                    Optional.of(new SHA2(224, new SHA2(512, detectionLocation), detectionLocation));
            case "SHA-512/256", "SHA512/256" ->
                    Optional.of(new SHA2(256, new SHA2(512, detectionLocation), detectionLocation));
            case "SHA3-224" -> Optional.of(new SHA3(224, detectionLocation));
            case "SHA3-256" -> Optional.of(new SHA3(256, detectionLocation));
            case "SHA3-384" -> Optional.of(new SHA3(384, detectionLocation));
            case "SHA3-512" -> Optional.of(new SHA3(512, detectionLocation));
            default -> Optional.empty();
        };
    }
}
