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
package com.ibm.mapper.mapper.pyca;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.Poly1305;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.model.algorithms.blake.BLAKE2b;
import com.ibm.mapper.model.algorithms.blake.BLAKE2s;
import com.ibm.mapper.model.algorithms.shake.SHAKE;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class PycaDigestMapper implements IMapper {
    @Override
    public @Nonnull Optional<MessageDigest> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "SHA1" -> Optional.of(new SHA(detectionLocation));
            case "SHA512_224" ->
                    Optional.of(new SHA2(224, new SHA2(512, detectionLocation), detectionLocation));
            case "SHA512_256" ->
                    Optional.of(new SHA2(256, new SHA2(512, detectionLocation), detectionLocation));
            case "SHA224" -> Optional.of(new SHA2(224, detectionLocation));
            case "SHA256" -> Optional.of(new SHA2(256, detectionLocation));
            case "SHA384" -> Optional.of(new SHA2(384, detectionLocation));
            case "SHA512" -> Optional.of(new SHA2(512, detectionLocation));
            case "SHA3_224" -> Optional.of(new SHA3(224, detectionLocation));
            case "SHA3_256" -> Optional.of(new SHA3(256, detectionLocation));
            case "SHA3_384" -> Optional.of(new SHA3(384, detectionLocation));
            case "SHA3_512" -> Optional.of(new SHA3(512, detectionLocation));
            case "SHAKE128" -> Optional.of(new SHAKE(128, detectionLocation));
            case "SHAKE256" -> Optional.of(new SHAKE(256, detectionLocation));
            case "MD5" -> Optional.of(new MD5(detectionLocation));
            case "BLAKE2B" -> Optional.of(new BLAKE2b(false, detectionLocation));
            case "BLAKE2S" -> Optional.of(new BLAKE2s(false, detectionLocation));
            case "SM3" -> Optional.of(new SM3(detectionLocation));
            case "POLY1305" -> Optional.of(new Poly1305(detectionLocation));
            default -> Optional.empty();
        };
    }
}
