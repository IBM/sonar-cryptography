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
import com.ibm.mapper.model.algorithms.ascon.Ascon128;
import com.ibm.mapper.model.algorithms.ascon.Ascon128a;
import com.ibm.mapper.model.algorithms.ascon.Ascon80pq;
import com.ibm.mapper.model.algorithms.elephant.Delirium;
import com.ibm.mapper.model.algorithms.elephant.Dumbo;
import com.ibm.mapper.model.algorithms.elephant.Jumbo;
import com.ibm.mapper.model.algorithms.isap.IsapA128;
import com.ibm.mapper.model.algorithms.isap.IsapA128a;
import com.ibm.mapper.model.algorithms.isap.IsapK128;
import com.ibm.mapper.model.algorithms.isap.IsapK128a;
import com.ibm.mapper.model.algorithms.photonbeetle.PhotonBeetleAEAD;
import com.ibm.mapper.model.algorithms.sparkle.Schwaemm;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcAeadEnumsMapper implements IMapper {

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
    private Optional<? extends Algorithm> map(
            @Nonnull String aeadString, @Nonnull DetectionLocation detectionLocation) {
        return switch (aeadString) {
            case "ascon128" -> Optional.of(new Ascon128(detectionLocation));
            case "ascon128a" -> Optional.of(new Ascon128a(detectionLocation));
            case "ascon80pq" -> Optional.of(new Ascon80pq(detectionLocation));
            case "elephant160" -> Optional.of(new Dumbo(detectionLocation));
            case "elephant176" -> Optional.of(new Jumbo(detectionLocation));
            case "elephant200" -> Optional.of(new Delirium(detectionLocation));
            case "ISAP_A_128" -> Optional.of(new IsapA128(detectionLocation));
            case "ISAP_A_128A" -> Optional.of(new IsapA128a(detectionLocation));
            case "ISAP_K_128" -> Optional.of(new IsapK128(detectionLocation));
            case "ISAP_K_128A" -> Optional.of(new IsapK128a(detectionLocation));
            case "pb128" -> Optional.of(new PhotonBeetleAEAD(128, detectionLocation));
            case "pb32" -> Optional.of(new PhotonBeetleAEAD(32, detectionLocation));
            case "SCHWAEMM128_128" -> Optional.of(new Schwaemm(128, 128, detectionLocation));
            case "SCHWAEMM256_128" -> Optional.of(new Schwaemm(256, 128, detectionLocation));
            case "SCHWAEMM256_256" -> Optional.of(new Schwaemm(256, 256, detectionLocation));
            case "SCHWAEMM192_192" -> Optional.of(new Schwaemm(192, 192, detectionLocation));
            default -> Optional.empty();
        };
    }
}
