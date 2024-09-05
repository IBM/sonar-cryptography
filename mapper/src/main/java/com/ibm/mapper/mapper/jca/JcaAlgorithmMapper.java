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
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaAlgorithmMapper implements IMapper {

    /** IMPORTANT: order matters here */
    private static final List<IMapper> jcaSpecificAlgorithmMappers =
            List.of(
                    // algorithms
                    new JcaCipherMapper(),
                    new JcaMacMapper(),
                    new JcaMessageDigestMapper(),
                    new JcaMGFMapper(),
                    new JcaPasswordBasedEncryptionMapper(),
                    new JcaPBKDFMapper(),
                    new JcaPRNGMapper(),
                    new JcaKeyAgreementMapper(),
                    new JcaSignatureMapper());

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        for (IMapper mapper : jcaSpecificAlgorithmMappers) {
            Optional<? extends INode> asset = mapper.parse(str, detectionLocation);
            if (asset.isPresent()) {
                return asset;
            }
        }

        return switch (str.toUpperCase().trim()) {
            case "DH", "DIFFIEHELLMAN" -> Optional.of(new DH(detectionLocation));
            case "RSA" -> Optional.of(new RSA(detectionLocation));
            case "EC" ->
                    Optional.of(new Algorithm(str, PublicKeyEncryption.class, detectionLocation));
            default -> {
                final Algorithm algorithm = new Algorithm(str, Unknown.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
