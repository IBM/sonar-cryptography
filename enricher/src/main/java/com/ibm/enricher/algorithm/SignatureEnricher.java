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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Signature;

import javax.annotation.Nonnull;
import java.util.Map;
import java.util.Optional;

public class SignatureEnricher implements ISignatureEnricher {

    @Override
    public void enrich(
            @Nonnull Signature signature,
            @Nonnull Map<Class<? extends INode>, INode> dependingNodes) {
        final Optional<MessageDigest> promiseMessageDigest = signature.getDigest();

        Map<Class<? extends INode>, INode> newDependingNodes = Map.of();
        if (promiseMessageDigest.isPresent()) {
            newDependingNodes = Map.of(MessageDigest.class, promiseMessageDigest.get());
        }

        final String signatureAlgorithmName =
                Utils.sanitiseAlgorithmName(signature.asString());
        switch (signatureAlgorithmName) {
            case "DSA" -> {
                final DSASignatureEnricher dsaSignatureEnricher = new DSASignatureEnricher();

                dsaSignatureEnricher.enrich(signature, newDependingNodes);
            }
            case "ECDSA" -> {
                final ECDSASignatureEnricher ecdsaSignatureEnricher = new ECDSASignatureEnricher();
                ecdsaSignatureEnricher.enrich(signature, newDependingNodes);
            }
            case "RSA" -> {
                if (signature.isProbabilisticSignatureScheme()) {
                    final RSASSASignatureEnricher rsassaSignatureEnricher =
                            new RSASSASignatureEnricher();
                    rsassaSignatureEnricher.enrich(signature, newDependingNodes);
                } else {
                    final RSASignatureEnricher rsaSignatureEnricher = new RSASignatureEnricher();
                    rsaSignatureEnricher.enrich(signature, newDependingNodes);
                }
            }
            default -> {
                // nothing
            }
        }
    }
}
