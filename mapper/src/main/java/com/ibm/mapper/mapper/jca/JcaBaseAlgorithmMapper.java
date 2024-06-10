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
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.commons.lang3.tuple.Pair;

class JcaBaseAlgorithmMapper implements IMapper {

    @Nonnull
    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    public static <T extends Algorithm> Optional<Algorithm> generalizeAlgorithm(
            @Nonnull Optional<T> optional) {
        if (optional.isEmpty()) {
            return Optional.empty();
        }
        T val = optional.get();
        return Optional.of(val);
    }

    @Nonnull
    @Override
    public Optional<Algorithm> parse(
            @Nullable final String str,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull final Configuration configuration) {
        return parseAndAddChildren(str, detectionLocation, configuration, new HashMap<>());
    }

    @Nonnull
    public Optional<Algorithm> parseAndAddChildren(
            @Nullable final String str,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull final Configuration configuration,
            @Nonnull Map<Class<? extends INode>, INode> children) {
        if (str == null) {
            return Optional.empty();
        }
        final Pair<String, Integer> algorithmWithKeySize = getDefaultKeySize(str);
        final String algorithmName = algorithmWithKeySize.getLeft();

        final Algorithm algorithm;
        // check for key length
        if (algorithmWithKeySize.getValue() != null) {
            // create key length node
            final KeyLength defaultKeyLength =
                    new KeyLength(
                            configuration.changeIntValue(algorithmWithKeySize.getValue()),
                            detectionLocation);
            algorithm = new Algorithm(algorithmName, defaultKeyLength, detectionLocation, children);
        } else {
            algorithm = new Algorithm(algorithmName, detectionLocation, children);
        }
        algorithm.apply(configuration);
        return Optional.of(algorithm);
    }

    /**
     * Source for the default key size's <a
     * href="https://docs.oracle.com/en/java/javase/17/security/oracle-providers.html">Default key
     * sizes</a>
     *
     * @param algorithm the algorithm string
     * @return a pair of algorithm and key size
     */
    @Nonnull
    private Pair<String, Integer> getDefaultKeySize(@Nonnull final String algorithm) {
        if (algorithm.contains("_")) {
            int index = algorithm.indexOf("_");
            String keyStr = algorithm.substring(index + 1);
            Integer size = Integer.parseInt(keyStr);
            return Pair.of(algorithm.substring(0, index), size);
        } else {
            return switch (algorithm.trim().toLowerCase()) {
                case "des" -> Pair.of(algorithm, 56);
                case "desede", "desedewrap" -> Pair.of(algorithm, 168);
                case "aes", "aeswrap", "arcfour", "blowfish", "ecies", "rc2", "rc4", "rc5" ->
                        Pair.of(algorithm, 128);
                case "sha-224", "hmacsha224" -> Pair.of(algorithm, 224);
                case "sha-384", "hmacsha384" -> Pair.of(algorithm, 384);
                case "chacha20", "sha-256", "hmacsha256" -> Pair.of(algorithm, 256);
                case "hmacmd5", "sha-1", "hmacsha1", "sha-512", "hmacsha512" ->
                        Pair.of(algorithm, 512);
                case "rsa" -> Pair.of(algorithm, 2048);
                case "diffiehellman" -> Pair.of(algorithm, 3072);
                default -> Pair.of(algorithm, null);
            };
        }
    }
}
