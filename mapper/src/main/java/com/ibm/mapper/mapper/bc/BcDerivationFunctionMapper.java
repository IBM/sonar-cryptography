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

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.ANSIX942;
import com.ibm.mapper.model.algorithms.ANSIX963;
import com.ibm.mapper.model.algorithms.ConcatenationKDF;
import com.ibm.mapper.model.algorithms.HKDF;
import com.ibm.mapper.model.algorithms.KDF1;
import com.ibm.mapper.model.algorithms.KDF2;
import com.ibm.mapper.model.algorithms.KDFCounter;
import com.ibm.mapper.model.algorithms.KDFDoublePipeline;
import com.ibm.mapper.model.algorithms.KDFFeedback;
import com.ibm.mapper.model.algorithms.KDFSession;
import com.ibm.mapper.model.algorithms.MGF1;
import com.ibm.mapper.model.functionality.KeyDerivation;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcDerivationFunctionMapper implements IMapper {

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
            @Nonnull String digestString, @Nonnull DetectionLocation detectionLocation) {
        return switch (digestString) {
            case "BrokenKDF2BytesGenerator" -> Optional.of(new KDF2(detectionLocation));
            case "ConcatenationKDFGenerator" ->
                    Optional.of(new ConcatenationKDF(detectionLocation));
            case "DHKEKGenerator" -> {
                // "RFC 2631 Diffie-hellman KEK derivation function"
                // https://datatracker.ietf.org/doc/html/rfc2631#section-2.1.3
                final KeyDerivationFunction kdf = new ANSIX942(detectionLocation);
                kdf.put(new KeyDerivation(detectionLocation));
                yield Optional.of(kdf);
            }
            case "ECDHKEKGenerator" -> {
                // "X9.63 based key derivation function for ECDH CMS"
                // https://csrc.nist.gov/CSRC/media/Events/Key-Management-Workshop-2000/documents/x963_overview.pdf
                final KeyDerivationFunction kdf = new ANSIX963(detectionLocation);
                kdf.put(new KeyDerivation(detectionLocation));
                yield Optional.of(new ANSIX963(detectionLocation));
            }
            /* case "HandshakeKDFFunction" -> Optional.of(); // TODO: which algorithm should it be mapped to? */
            case "GSKKFDGenerator" -> Optional.of(new KDFSession(detectionLocation));
            case "HKDFBytesGenerator" -> Optional.of(new HKDF(detectionLocation));
            case "KDF1BytesGenerator" -> Optional.of(new KDF1(detectionLocation));
            case "KDF2BytesGenerator" -> Optional.of(new KDF2(detectionLocation));
            case "KDFCounterBytesGenerator" -> Optional.of(new KDFCounter(detectionLocation));
            case "KDFDoublePipelineIterationBytesGenerator" ->
                    Optional.of(new KDFDoublePipeline(detectionLocation));
            case "KDFFeedbackBytesGenerator" -> Optional.of(new KDFFeedback(detectionLocation));
            case "MGF1BytesGenerator" -> Optional.of(new MGF1(detectionLocation));
            default -> {
                final Algorithm algorithm =
                        new Algorithm(digestString, MessageDigest.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
