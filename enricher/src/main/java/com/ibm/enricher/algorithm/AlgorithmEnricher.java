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
import com.ibm.mapper.model.*;
import java.util.Map;
import javax.annotation.Nonnull;

public class AlgorithmEnricher implements IAlgorithmEnricher {

    @Override
    public void enrich(
            @Nonnull Algorithm algorithm,
            @Nonnull Map<Class<? extends INode>, INode> dependingNodes) {
        final String algorithmName = Utils.sanitiseAlgorithmName(algorithm.asString());
        if (algorithm instanceof Signature signature) {
            final SignatureEnricher signatureEnricher = new SignatureEnricher();
            signatureEnricher.enrich(signature, Map.of());
        } else if (algorithm instanceof MessageDigest || algorithm instanceof Mac) {
            final HashAlgorithmEnricher hashAlgorithmEnricher = new HashAlgorithmEnricher();
            hashAlgorithmEnricher.enrich(algorithm, dependingNodes);
        } else {
            switch (algorithmName) {
                case "RSA" -> {
                    final Oid oid =
                            new Oid("1.2.840.113549.1.1.1", algorithm.getDetectionContext());
                    algorithm.append(oid);
                }
                case "DIFFIEHELLMAN" -> {
                    final Oid oid =
                            new Oid("1.2.840.113549.1.3.1", algorithm.getDetectionContext());
                    algorithm.append(oid);
                }
                case "AES" -> {
                    final AESEnricher aesEnricher = new AESEnricher();
                    aesEnricher.enrich(algorithm, dependingNodes);
                }
                default -> {
                    // nothing
                }
            }
        }
    }
}
