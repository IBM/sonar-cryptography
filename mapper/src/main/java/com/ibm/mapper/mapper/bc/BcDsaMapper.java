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
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.DSTU4145;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.ECNR;
import com.ibm.mapper.model.algorithms.gost.GOSTR341012;
import com.ibm.mapper.model.algorithms.gost.GOSTR341094;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcDsaMapper implements IMapper {

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
            @Nonnull String dsaString, @Nonnull DetectionLocation detectionLocation) {
        return switch (dsaString) {
            case "DSASigner" -> Optional.of(new DSA(detectionLocation));
            case "DSTU4145Signer" -> Optional.of(new DSTU4145(detectionLocation));
            case "ECDSASigner" -> Optional.of(new ECDSA(detectionLocation));
            case "ECGOST3410_2012Signer" -> Optional.of(new GOSTR341012(detectionLocation));
            case "ECGOST3410Signer" -> Optional.of(new GOSTR341012(detectionLocation));
            case "ECNRSigner" -> Optional.of(new ECNR(detectionLocation));
            case "GOST3410Signer" -> Optional.of(new GOSTR341094(detectionLocation));
            default -> {
                final Algorithm algorithm =
                        new Algorithm(dsaString, Signature.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
