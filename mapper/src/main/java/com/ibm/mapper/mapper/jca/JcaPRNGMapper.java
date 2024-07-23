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

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PseudorandomNumberGenerator;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.*;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaPRNGMapper implements IMapper {

    private static final List<String> validValues =
            List.of(
                    "NativePRNG",
                    "NativePRNGBlocking",
                    "NativePRNGNonBlocking",
                    "PKCS11",
                    "DRBG",
                    "SHA1PRNG",
                    "Windows-PRNG");

    @Nonnull
    @Override
    public Optional<PseudorandomNumberGenerator> parse(
            @Nullable String str,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }

        if (!reflectValidValues(str)) {
            return Optional.empty();
        }

        Map<Class<? extends INode>, INode> assets = new HashMap<>();
        if (str.contains("SHA1")) {
            JcaMessageDigestMapper jcaMessageDigestMapper = new JcaMessageDigestMapper();
            Optional<MessageDigest> messageDigestOptional =
                    jcaMessageDigestMapper.parse("SHA-1", detectionLocation, configuration);
            messageDigestOptional.ifPresent(digest -> assets.put(digest.getKind(), digest));
        }

        JcaBaseAlgorithmMapper jcaBaseAlgorithmMapper = new JcaBaseAlgorithmMapper();
        Optional<Algorithm> algorithm =
                jcaBaseAlgorithmMapper.parseAndAddChildren(
                        str, detectionLocation, configuration, assets);
        if (algorithm.isEmpty()) {
            return Optional.empty();
        }
        PseudorandomNumberGenerator prng =
                new PseudorandomNumberGenerator(algorithm.get());
        return Optional.of(prng);
    }

    private boolean reflectValidValues(@Nonnull String str) {
        return validValues.stream().anyMatch(str::equalsIgnoreCase);
    }
}
