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
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcAeadParametersMapper implements IMapper {

    // case "ascon128", "SCHWAEMM128_128", "ascon128a", "SCHWAEMM256_128":
    //     keySize = 128;
    //     break;
    // case "ascon80pq":
    //     keySize = 160;
    //     break;
    // case "SCHWAEMM192_192":
    //     keySize = 192;
    //     break;
    // case "SCHWAEMM256_256":
    //     keySize = 256;
    //     break;

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
            case "ascon128" -> Optional.of(new Ascon128(detectionLocation));
            case "ascon128a" -> Optional.of(new Ascon128a(detectionLocation));
            case "ascon80pq" -> Optional.of(new Ascon80pq(detectionLocation));
            case "elephant160" -> Optional.of(new Dumbo(detectionLocation));
            case "elephant176" -> Optional.of(new Jumbo(detectionLocation));
            case "elephant200" -> Optional.of(new Delirium(detectionLocation));
            case "SCHWAEMM128_128" -> Optional.empty();
            case "SCHWAEMM256_128" -> Optional.empty();
            case "SCHWAEMM256_256" -> Optional.empty();
            case "SCHWAEMM192_192" -> Optional.empty();
            default -> Optional.empty();
        };
    }
}
