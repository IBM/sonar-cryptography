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
import com.ibm.mapper.mapper.ssl.json.JsonCipherSuite;
import com.ibm.mapper.mapper.ssl.json.JsonCipherSuites;
import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Identifier;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public final class CipherSuiteMapper implements IMapper {

    @NotNull @Override
    public Optional<? extends INode> parse(
            @Nullable String str, @NotNull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        Optional<JsonCipherSuite> possibleJsonCipherSuite = findCipherSuite(str);
        if (possibleJsonCipherSuite.isEmpty()) {
            // return a 'simple' cipher object
            return Optional.of(new Unknown(str, detectionLocation));
        }
        final JsonCipherSuite jsonCipherSuite = possibleJsonCipherSuite.get();

        List<INode> assets = new ArrayList<>();
        // key agreement
        jsonCipherSuite
                .getKexAlgorithm()
                .flatMap(
                        algoStr -> {
                            final KeyExchangeAlgorithmMapper keyExchangeAlgorithmMapper =
                                    new KeyExchangeAlgorithmMapper();
                            return keyExchangeAlgorithmMapper.parse(algoStr, detectionLocation);
                        })
                .ifPresent(assets::add);
        // authentication agreement
        jsonCipherSuite
                .getAuthAlgorithm()
                .flatMap(
                        algoStr -> {
                            final AuthenticationAlgorithmMapper authenticationAlgorithmMapper =
                                    new AuthenticationAlgorithmMapper();
                            return authenticationAlgorithmMapper.parse(algoStr, detectionLocation);
                        })
                .ifPresent(assets::add);
        // encryption algorithm
        jsonCipherSuite
                .getEncAlgorithm()
                .flatMap(
                        algoStr -> {
                            final EncryptionAlgorithmMapper encryptionAlgorithmMapper =
                                    new EncryptionAlgorithmMapper();
                            return encryptionAlgorithmMapper.parse(algoStr, detectionLocation);
                        })
                .ifPresent(assets::add);
        // hash algorithm
        jsonCipherSuite
                .getHashAlgorithm()
                .flatMap(
                        algoStr -> {
                            final HashAlgorithmMapper hashAlgorithmMapper =
                                    new HashAlgorithmMapper();
                            return hashAlgorithmMapper.parse(algoStr, detectionLocation);
                        })
                .ifPresent(assets::add);

        final CipherSuite cipherSuite =
                new CipherSuite(
                        jsonCipherSuite.getIanaName(),
                        new AssetCollection(assets),
                        detectionLocation);
        jsonCipherSuite
                .getIdentifiers()
                .flatMap(
                        ids -> {
                            final List<Identifier> identifiers =
                                    Arrays.stream(ids)
                                            .map(idStr -> new Identifier(idStr, detectionLocation))
                                            .toList();
                            return Optional.of(identifiers.stream());
                        })
                .map(identifierStream -> new IdentifierCollection(identifierStream.toList()))
                .ifPresent(cipherSuite::append);

        return Optional.of(cipherSuite);
    }

    @Nonnull
    public static Optional<JsonCipherSuite> findCipherSuite(@Nonnull final String identifier) {
        return Optional.ofNullable(JsonCipherSuites.CIPHER_SUITES.get(identifier))
                .or(
                        () -> {
                            Collection<JsonCipherSuite> suites =
                                    JsonCipherSuites.CIPHER_SUITES.values();
                            for (JsonCipherSuite suite : suites) {
                                if (suite.getGnutlsName().isPresent()
                                        && suite.getGnutlsName().get().equals(identifier)) {
                                    return Optional.of(suite);
                                }
                                if (suite.getOpensslName().isPresent()
                                        && suite.getOpensslName().get().equals(identifier)) {
                                    return Optional.of(suite);
                                }
                            }
                            return Optional.empty();
                        });
    }
}
