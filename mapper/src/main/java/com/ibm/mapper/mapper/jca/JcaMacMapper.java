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
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaMacMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends IAlgorithm> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        // check if it is pbe
        JcaPasswordBasedEncryptionMapper pbeMapper = new JcaPasswordBasedEncryptionMapper();
        Optional<PasswordBasedEncryption> pbeOptional = pbeMapper.parse(str, detectionLocation);
        if (pbeOptional.isPresent()) {
            // pbe
            return pbeOptional;
        }

        if (str.toLowerCase().contains("with") || !str.toLowerCase().contains("hmac")) {
            return Optional.empty();
        }

        final String messageDigestStr =
                str.substring(str.toLowerCase().trim().indexOf("Hmac".toLowerCase()) + 4);

        return Optional.of(messageDigestStr.toUpperCase().trim())
                .map(
                        s ->
                                switch (s) {
                                    case "MD2" -> new MD2(detectionLocation);
                                    case "MD5" -> new MD5(detectionLocation);
                                    case "SHA", "SHA1", "SHA-1" -> new SHA(detectionLocation);
                                    case "SHA-224", "SHA224" -> new SHA2(224, detectionLocation);
                                    case "SHA-256", "SHA256" -> new SHA2(256, detectionLocation);
                                    case "SHA-384", "SHA384" -> new SHA2(384, detectionLocation);
                                    case "SHA-512", "SHA512" -> new SHA2(512, detectionLocation);
                                    case "SHA-512/224", "SHA512/224" ->
                                            new SHA2(
                                                    224,
                                                    new SHA2(512, detectionLocation),
                                                    detectionLocation);
                                    case "SHA-512/256", "SHA512/256" ->
                                            new SHA2(
                                                    256,
                                                    new SHA2(512, detectionLocation),
                                                    detectionLocation);
                                    case "SHA3-224" -> new SHA3(224, detectionLocation);
                                    case "SHA3-256" -> new SHA3(256, detectionLocation);
                                    case "SHA3-384" -> new SHA3(384, detectionLocation);
                                    case "SHA3-512" -> new SHA3(512, detectionLocation);
                                    default -> null;
                                })
                .map(HMAC::new);
    }
}
