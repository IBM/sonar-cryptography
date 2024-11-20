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
package com.ibm.enricher.algorithm;

import com.ibm.enricher.IEnricher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.SHA2;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

public class SHA2Enricher implements IEnricher {
    @Nonnull
    @Override
    public INode enrich(@Nonnull INode node) {
        if (node instanceof SHA2 sha2) {
            return enrich(sha2);
        }
        return node;
    }

    @Nonnull
    private SHA2 enrich(@Nonnull SHA2 sha2) {
        sha2.getDigestSize()
                .ifPresent(
                        digestSize -> {
                            switch (digestSize.getValue()) {
                                case 256 -> {
                                    final Optional<INode> preHashOptional =
                                            sha2.hasChildOfType(MessageDigest.class);
                                    preHashOptional.ifPresentOrElse(
                                            preHash ->
                                                    evaluatePreHash(
                                                            sha2,
                                                            preHash,
                                                            () ->
                                                                    Stream.of(
                                                                            new BlockSize(
                                                                                    1024,
                                                                                    sha2
                                                                                            .getDetectionContext()),
                                                                            new Oid(
                                                                                    "2.16.840.1.101.3.4.2.6",
                                                                                    sha2
                                                                                            .getDetectionContext()))),
                                            () -> {
                                                sha2.put(
                                                        new BlockSize(
                                                                512, sha2.getDetectionContext()));
                                                sha2.put(
                                                        new Oid(
                                                                "2.16.840.1.101.3.4.2.1",
                                                                sha2.getDetectionContext()));
                                            });
                                }
                                case 384 -> {
                                    sha2.put(new BlockSize(1024, sha2.getDetectionContext()));
                                    sha2.put(
                                            new Oid(
                                                    "2.16.840.1.101.3.4.2.2",
                                                    sha2.getDetectionContext()));
                                }
                                case 512 -> {
                                    sha2.put(new BlockSize(1024, sha2.getDetectionContext()));
                                    sha2.put(
                                            new Oid(
                                                    "2.16.840.1.101.3.4.2.3",
                                                    sha2.getDetectionContext()));
                                }
                                case 224 -> {
                                    final Optional<INode> preHashOptional =
                                            sha2.hasChildOfType(MessageDigest.class);
                                    preHashOptional.ifPresentOrElse(
                                            preHash ->
                                                    evaluatePreHash(
                                                            sha2,
                                                            preHash,
                                                            () ->
                                                                    Stream.of(
                                                                            new BlockSize(
                                                                                    1024,
                                                                                    sha2
                                                                                            .getDetectionContext()),
                                                                            new Oid(
                                                                                    "2.16.840.1.101.3.4.2.5",
                                                                                    sha2
                                                                                            .getDetectionContext()))),
                                            () -> {
                                                sha2.put(
                                                        new BlockSize(
                                                                512, sha2.getDetectionContext()));
                                                sha2.put(
                                                        new Oid(
                                                                "2.16.840.1.101.3.4.2.4",
                                                                sha2.getDetectionContext()));
                                            });
                                }
                                default -> {
                                    // nothing
                                }
                            }
                        });
        return sha2;
    }

    private void evaluatePreHash(
            @Nonnull SHA2 sha2,
            @Nonnull INode preHash,
            @Nonnull Supplier<Stream<INode>> childNodeSupplier) {
        if (preHash instanceof SHA2) {
            preHash.hasChildOfType(DigestSize.class)
                    .map(d -> ((DigestSize) d).getValue())
                    .ifPresent(
                            size -> {
                                if (size == 512) {
                                    childNodeSupplier.get().forEach(sha2::put);
                                }
                            });
        }
    }
}
