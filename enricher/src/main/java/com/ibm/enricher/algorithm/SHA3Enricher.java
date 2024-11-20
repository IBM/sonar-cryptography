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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.SHA3;
import javax.annotation.Nonnull;

public class SHA3Enricher implements IEnricher {

    @Override
    public @Nonnull INode enrich(@Nonnull INode node) {
        if (node instanceof SHA3 sha3) {
            return enrich(sha3);
        }
        return node;
    }

    @Nonnull
    private SHA3 enrich(@Nonnull SHA3 sha3) {
        sha3.getDigestSize()
                .ifPresent(
                        digestSize -> {
                            switch (digestSize.getValue()) {
                                case 224 -> {
                                    sha3.put(new BlockSize(1152, sha3.getDetectionContext()));
                                    sha3.put(
                                            new Oid(
                                                    "2.16.840.1.101.3.4.2.7",
                                                    sha3.getDetectionContext()));
                                }
                                case 256 -> {
                                    sha3.put(new BlockSize(1088, sha3.getDetectionContext()));
                                    sha3.put(
                                            new Oid(
                                                    "2.16.840.1.101.3.4.2.8",
                                                    sha3.getDetectionContext()));
                                }
                                case 384 -> {
                                    sha3.put(new BlockSize(832, sha3.getDetectionContext()));
                                    sha3.put(
                                            new Oid(
                                                    "2.16.840.1.101.3.4.2.9",
                                                    sha3.getDetectionContext()));
                                }
                                case 512 -> {
                                    sha3.put(new BlockSize(576, sha3.getDetectionContext()));
                                    sha3.put(
                                            new Oid(
                                                    "2.16.840.1.101.3.4.2.10",
                                                    sha3.getDetectionContext()));
                                }
                                default -> {
                                    // nothing
                                }
                            }
                        });
        return sha3;
    }
}
