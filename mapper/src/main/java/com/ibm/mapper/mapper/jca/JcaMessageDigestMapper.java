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
import com.ibm.mapper.model.*;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaMessageDigestMapper implements IMapper {
    private static final List<String> validValues =
            List.of(
                    "MD2",
                    "MD5",
                    "SHA-1",
                    "SHA-224",
                    "SHA-256",
                    "SHA-384",
                    "SHA-512/224",
                    "SHA-512/256",
                    "SHA-512",
                    "SHA3-224",
                    "SHA3-256",
                    "SHA3-384",
                    "SHA3-512");

    // in bits
    private static Optional<Integer> getDigestSize(@Nullable final String str) {
        if (str == null) {
            return Optional.empty();
        }

        final String generalizedStr = str.toLowerCase().trim();
        return switch (generalizedStr) {
            case "md2", "md5" -> Optional.of(128);
            case "sha-1" -> Optional.of(160);
            case "sha-224", "sha-512/224", "sha3-224" -> Optional.of(224);
            case "sha-256", "sha-512/256", "sha3-256" -> Optional.of(256);
            case "sha-384", "sha3-384" -> Optional.of(384);
            case "sha-512", "sha3-512" -> Optional.of(512);
            default -> Optional.empty();
        };
    }

    // in bits
    private static Optional<Integer> getBlockSize(@Nullable final String str) {
        if (str == null) {
            return Optional.empty();
        }

        final String generalizedStr = str.toLowerCase().trim();
        return switch (generalizedStr) {
            case "md2" -> Optional.of(128);
            case "md5", "sha-1", "sha-224", "sha-256" -> Optional.of(512);
            case "sha-384", "sha-512", "sha-512/224", "sha-512/256" -> Optional.of(1024);
            case "sha3-224" -> Optional.of(1152);
            case "sha3-256" -> Optional.of(1088);
            case "sha3-384" -> Optional.of(832);
            case "sha3-512" -> Optional.of(576);
            default -> Optional.empty();
        };
    }

    @Nonnull
    @Override
    public Optional<MessageDigest> parse(
            @Nullable final String str,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull final Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }

        final String sanatizedString = sanitize(str);
        if (!reflectValidValues(sanatizedString)) {
            return Optional.empty();
        }

        JcaBaseAlgorithmMapper algorithmMapper = new JcaBaseAlgorithmMapper();
        Map<Class<? extends INode>, INode> assets = new HashMap<>();
        final String generalizedStr = sanatizedString.toLowerCase().trim();
        if (generalizedStr.contains("/")) {
            int slashPos = generalizedStr.indexOf("/");
            String firstHash = sanatizedString.substring(0, slashPos);
            String secondHash = "SHA-" + sanatizedString.substring(slashPos + 1);
            if (reflectValidValues(firstHash)) {
                algorithmMapper
                        .parse(firstHash, detectionLocation, configuration)
                        .ifPresent(
                                algorithm ->
                                        assets.put(
                                                MessageDigest.class,
                                                new MessageDigest(
                                                        algorithm,
                                                        getDigestSize(firstHash)
                                                                .map(
                                                                        digestStr ->
                                                                                new DigestSize(
                                                                                        digestStr,
                                                                                        detectionLocation))
                                                                .orElse(null),
                                                        getBlockSize(firstHash)
                                                                .map(
                                                                        blockStr ->
                                                                                new BlockSize(
                                                                                        blockStr,
                                                                                        detectionLocation))
                                                                .orElse(null),
                                                        detectionLocation)));
            }
            if (reflectValidValues(secondHash)) {
                algorithmMapper
                        .parse(secondHash, detectionLocation, configuration)
                        .ifPresent(
                                algorithm ->
                                        assets.put(
                                                MessageDigest.class,
                                                new MessageDigest(
                                                        algorithm,
                                                        getDigestSize(secondHash)
                                                                .map(
                                                                        digestStr ->
                                                                                new DigestSize(
                                                                                        digestStr,
                                                                                        detectionLocation))
                                                                .orElse(null),
                                                        getBlockSize(secondHash)
                                                                .map(
                                                                        blockStr ->
                                                                                new BlockSize(
                                                                                        blockStr,
                                                                                        detectionLocation))
                                                                .orElse(null),
                                                        detectionLocation)));
            }
        }

        Optional<Algorithm> algorithmOptional =
                algorithmMapper.parseAndAddChildren(
                        sanatizedString, detectionLocation, configuration, assets);
        if (algorithmOptional.isEmpty()) {
            return Optional.empty();
        }

        MessageDigest messageDigest =
                new MessageDigest(
                        algorithmOptional.get(),
                        getDigestSize(sanatizedString)
                                .map(digestStr -> new DigestSize(digestStr, detectionLocation))
                                .orElse(null),
                        getBlockSize(sanatizedString)
                                .map(blockStr -> new BlockSize(blockStr, detectionLocation))
                                .orElse(null),
                        detectionLocation);
        return Optional.of(messageDigest);
    }

    @Nonnull
    private String sanitize(@Nonnull final String str) {
        if (str.contains("-") || !str.toLowerCase().contains("sha")) {
            return str;
        }
        if (str.toLowerCase().contains("sha3") && !str.toLowerCase().contains("sha38")) {
            return Utils.addChar(str, '-', 4);
        }
        return Utils.addChar(str, '-', 3);
    }

    private boolean reflectValidValues(@Nonnull String str) {
        return validValues.stream().anyMatch(str::equalsIgnoreCase);
    }
}
