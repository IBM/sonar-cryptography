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
package com.ibm.mapper.mapper.ssl;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.ECCPWD;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.Kerberos;
import com.ibm.mapper.model.algorithms.PSK;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SRP;
import com.ibm.mapper.model.algorithms.gost.GOSTR341112;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class KeyExchangeAlgorithmMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends Algorithm> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str) {
            case "DHE", "DH" -> Optional.of(new DH(KeyAgreement.class, detectionLocation));
            case "SRP" -> Optional.of(new SRP(detectionLocation));
            case "RSA" -> Optional.of(new RSA(KeyAgreement.class, detectionLocation));
            case "ECDH", "ECDHE" -> Optional.of(new ECDH(detectionLocation));
            case "ECCPWD" -> Optional.of(new ECCPWD(detectionLocation));
            case "PSK" -> Optional.of(new PSK(detectionLocation));
            case "KRB5" -> Optional.of(new Kerberos(5, detectionLocation));
            case "GOSTR341112" -> Optional.of(new GOSTR341112(detectionLocation));
            case "GOSTR341112 256" -> Optional.of(new GOSTR341112(256, detectionLocation));
            default -> Optional.empty();
        };
    }
}
