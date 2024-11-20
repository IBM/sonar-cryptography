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
package com.ibm.mapper.mapper.bc;

import com.ibm.mapper.ITranslator;
import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.ANSIX931;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.ISO9796;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.model.algorithms.SM2;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcSignatureMapper implements IMapper {

    @Override
    @Nonnull
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        return map(str, detectionLocation);
    }

    @Nonnull
    private Optional<? extends INode> map(
            @Nonnull String signerString, @Nonnull DetectionLocation detectionLocation) {
        return switch (signerString) {
            case "DigestingMessageSigner",
                    "DigestingStateAwareMessageSigner",
                    "GenericSigner",
                    "DSADigestSigner" ->
                    Optional.of(
                            new Algorithm(ITranslator.UNKNOWN, Signature.class, detectionLocation));
            case "Ed25519ctxSigner" -> Optional.of(new Ed25519(detectionLocation));
            case "Ed25519phSigner" -> Optional.of(new Ed25519(detectionLocation));
            case "Ed25519Signer" -> Optional.of(new Ed25519(detectionLocation));
            case "Ed448phSigner" -> Optional.of(new Ed448(detectionLocation));
            case "Ed448Signer" -> Optional.of(new Ed448(detectionLocation));
            case "ISO9796d2PSSSigner" ->
                    Optional.of(new ISO9796(ProbabilisticSignatureScheme.class, detectionLocation));
            case "ISO9796d2Signer" -> Optional.of(new ISO9796(detectionLocation));
            case "PSSSigner" -> Optional.of(new RSAssaPSS(detectionLocation));
            case "RSADigestSigner" -> Optional.of(new RSA(Signature.class, detectionLocation));
            case "SM2Signer" -> Optional.of(new SM2(detectionLocation));
            case "X931Signer" -> Optional.of(new ANSIX931(detectionLocation));
            default -> {
                final Algorithm algorithm =
                        new Algorithm(signerString, Signature.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
