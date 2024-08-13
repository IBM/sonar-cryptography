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
import com.ibm.mapper.model.algorithms.ascon.Ascon;
import com.ibm.mapper.model.algorithms.elephant.Elephant;
import com.ibm.mapper.model.algorithms.grain.Grain128AEAD;
import com.ibm.mapper.model.algorithms.isap.Isap;
import com.ibm.mapper.model.algorithms.photonbeetle.PhotonBeetleAEAD;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcAeadMapper implements IMapper {

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
            @Nonnull String cipherAlgorithm, @Nonnull DetectionLocation detectionLocation) {
        return switch (cipherAlgorithm) {
            case "AsconEngine" -> Optional.of(new Ascon(detectionLocation));
            case "ElephantEngine" -> Optional.of(new Elephant(detectionLocation));
            case "Grain128AEADEngine" -> Optional.of(new Grain128AEAD(detectionLocation));
            case "IsapEngine" -> Optional.of(new Isap(detectionLocation));
            case "PhotonBeetleEngine" -> Optional.of(new PhotonBeetleAEAD(detectionLocation));
            // case "SparkleEngine" -> Optional.of();
            // case "XoodyakEngine" -> Optional.of();
            default -> {
                System.out.println(cipherAlgorithm);
                yield Optional.empty();
            }
        };
    }
}