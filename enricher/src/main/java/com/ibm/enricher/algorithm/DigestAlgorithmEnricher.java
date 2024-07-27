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

import com.ibm.enricher.utils.Utils;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import java.util.Map;
import javax.annotation.Nonnull;

public class DigestAlgorithmEnricher implements IAlgorithmEnricher {

    private static final String NIST_HASH_OID_BASE = "2.16.840.1.101.3.4.2";

    @Override
    public void enrich(
            @Nonnull Algorithm algorithm,
            @Nonnull Map<Class<? extends INode>, INode> dependingNodes) {
        final String algorithmName = Utils.sanitiseAlgorithmName(algorithm.asString());
        switch (algorithmName) {
            case "SHA-1" -> {
                final Oid oid = new Oid("1.3.14.3.2.26", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHA-256" -> {
                final Oid oid = new Oid(NIST_HASH_OID_BASE + ".1", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHA-384" -> {
                final Oid oid = new Oid(NIST_HASH_OID_BASE + ".2", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHA-512" -> {
                final Oid oid = new Oid(NIST_HASH_OID_BASE + ".3", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHA-224" -> {
                final Oid oid = new Oid(NIST_HASH_OID_BASE + ".4", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHA-512/224" -> {
                final Oid oid = new Oid(NIST_HASH_OID_BASE + ".5", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHA-512/256" -> {
                final Oid oid = new Oid(NIST_HASH_OID_BASE + ".6", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHA3-224" -> {
                final Oid oid = new Oid(NIST_HASH_OID_BASE + ".7", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHA3-256" -> {
                final Oid oid = new Oid(NIST_HASH_OID_BASE + ".8", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHA3-384" -> {
                final Oid oid = new Oid(NIST_HASH_OID_BASE + ".9", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHA3-512" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".10", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHAKE-128" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".11", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHAKE-256" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".12", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "HMACWITHSHA3-224" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".13", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "HMACWITHSHA3-256" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".14", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "HMACWITHSHA3-384" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".15", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "HMACWITHSHA3-512" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".16", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHAKE-128-LEN" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".17", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "SHAKE-256-LEN" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".18", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "KMACWITHSHAKE-128" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".19", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            case "KMACWITHSHAKE-256" -> {
                final Oid oid =
                        new Oid(NIST_HASH_OID_BASE + ".20", algorithm.getDetectionContext());
                algorithm.append(oid);
            }
            default -> {
                // nothing
            }
        }
    }
}
