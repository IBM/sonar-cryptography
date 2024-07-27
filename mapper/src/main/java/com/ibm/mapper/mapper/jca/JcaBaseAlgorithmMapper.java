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
package com.ibm.mapper.mapper.jca;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.algorithm.AES;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Optional;

class JcaBaseAlgorithmMapper implements IMapper {
    @Nonnull
    @Override
    public Optional<Algorithm> parse(
            @Nullable final String str,
            @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        String algorithmStr = str;
        @Nullable final Integer keySize;
        if (str.contains("_")) {
            String keyStr = str.substring(str.indexOf("_") + 1);
            algorithmStr = str.substring(0, str.indexOf("_"));
            keySize = Integer.parseInt(keyStr);
        } else {
            keySize = null;
        }

        return Optional.ofNullable(map(algorithmStr))
                .map(name -> new Algorithm(name, detectionLocation))
                .map(algorithm -> {
                    if (keySize != null) {
                        algorithm.append(new KeyLength(keySize, detectionLocation));
                    }
                    return algorithm;
                });
    }

    @Nullable
    private Optional<? extends Algorithm> map(@Nonnull String algorithm) {
        return switch (algorithm.toUpperCase().trim()) {
            case "AES" -> new AES()
            case "SHA1" -> Algorithm.Name.SHA1;
            case "SHA" -> Algorithm.Name.SHA;
            case "SHA3" -> Algorithm.Name.SHA3;
            case "BLOWFISH" -> Algorithm.Name.BLOWFISH;
            case "DES" -> Algorithm.Name.DES;
            case "DESEDE", "TRIPLEDES" -> Algorithm.Name.DESEDE;
            case "RC2" -> Algorithm.Name.RC2;
            case "RC4", "ARCFOUR" -> Algorithm.Name.RC4;
            case "RC5" -> Algorithm.Name.RC5;
            case "RSA" -> Algorithm.Name.RSA;
            case "DSA" -> Algorithm.Name.DSA;
            case "MD2" -> Algorithm.Name.MD2;
            case "MD5" -> Algorithm.Name.MD5;
            case "CHACHA20" -> Algorithm.Name.CHA_CHA_20;
            case "POLY1305" -> Algorithm.Name.POLY1305;
            case "DH", "DIFFIEHELLMAN" -> Algorithm.Name.DH;
            case "ECDH" -> Algorithm.Name.ECDH;
            case "EDDSA" -> Algorithm.Name.ED_DSA;
            case "ED25519" -> Algorithm.Name.ED_25519;
            case "ED448" -> Algorithm.Name.ED_448;
            case "X25519" -> Algorithm.Name.X25519;
            case "X448" -> Algorithm.Name.X448;
            case "XDH" -> Algorithm.Name.XDH;
            default -> null;
        };
    }
}
