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
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.ECMQV;
import com.ibm.mapper.model.algorithms.MQV;
import com.ibm.mapper.model.algorithms.XDH;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcAgreementMapper implements IMapper {

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
            @Nonnull String agreementString, @Nonnull DetectionLocation detectionLocation) {
        return switch (agreementString) {
            case "DHBasicAgreement" -> Optional.of(new DH(detectionLocation));
            case "ECDHBasicAgreement" -> Optional.of(new ECDH(detectionLocation)); // ECSVDP-DH
            case "ECDHCBasicAgreement" -> Optional.of(new ECDH(detectionLocation)); // ECSVDP-DHC
            case "ECDHCStagedAgreement" -> Optional.of(new ECDH(detectionLocation));
            case "ECMQVBasicAgreement" -> Optional.of(new ECMQV(detectionLocation));
            case "MQVBasicAgreement" -> Optional.of(new MQV(detectionLocation));
            case "XDHBasicAgreement" -> Optional.of(new XDH(detectionLocation));
            default -> {
                final Algorithm algorithm =
                        new Algorithm(agreementString, KeyAgreement.class, detectionLocation);
                algorithm.put(new Unknown(detectionLocation));
                yield Optional.of(algorithm);
            }
        };
    }
}
