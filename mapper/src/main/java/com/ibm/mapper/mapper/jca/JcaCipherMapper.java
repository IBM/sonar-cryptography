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

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.*;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaCipherMapper implements IMapper {
    private static final List<String> blockCiphers =
            List.of(
                    "AES",
                    "AES_128",
                    "AES_192",
                    "AES_256",
                    "AESWrap",
                    "AESWrap_128",
                    "AESWrap_192",
                    "AESWrap_256",
                    "Blowfish",
                    "DES",
                    "DESede",
                    "DESedeWrap",
                    "RC2",
                    "RC5");

    private static final List<String> streamCiphers =
            List.of("ARCFOUR", "ChaCha20", "ECIES", "RC4");

    public JcaCipherMapper() {
        // nothing
    }

    @Nonnull
    @Override
    public Optional<Algorithm> parse(
            @Nullable final String str,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull final Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }

        String algorithmStr;
        Optional<Mode> modeOptional = Optional.empty();
        Optional<Padding> paddingOptional = Optional.empty();

        if (str.contains("/")) {
            int slashIndex = str.indexOf("/");
            algorithmStr = str.substring(0, slashIndex);

            String rest = str.substring(slashIndex + 1);
            if (rest.contains("/")) {
                slashIndex = rest.indexOf("/");
                // mode
                String modeStr = rest.substring(0, slashIndex);
                JcaModeMapper jcaModeMapper = new JcaModeMapper();
                modeOptional = jcaModeMapper.parse(modeStr, detectionLocation, configuration);
                // padding
                String paddingStr = rest.substring(slashIndex + 1);
                JcaOAEPPaddingMapper jcaOAEPPaddingMapper = new JcaOAEPPaddingMapper();
                Optional<OptimalAsymmetricEncryptionPadding> oaepPaddingOptional =
                        jcaOAEPPaddingMapper.parse(str, detectionLocation, configuration);
                if (oaepPaddingOptional.isPresent()) {
                    paddingOptional = JcaBasePaddingMapper.generalizePadding(oaepPaddingOptional);
                } else {
                    JcaBasePaddingMapper jcaBasePaddingMapper = new JcaBasePaddingMapper();
                    paddingOptional =
                            jcaBasePaddingMapper.parse(
                                    paddingStr, detectionLocation, configuration);
                }
            }
        } else {
            algorithmStr = str;
        }

        // check if it is pbe
        JcaPasswordBasedEncryptionMapper pbeMapper = new JcaPasswordBasedEncryptionMapper();
        Optional<PasswordBasedEncryption> pbeOptional =
                pbeMapper.parse(algorithmStr, detectionLocation, configuration);
        if (pbeOptional.isPresent()) {
            return JcaBaseAlgorithmMapper.generalizeAlgorithm(pbeOptional);
        }

        // check if algorithm is a cipher
        if (!reflectValidValues(algorithmStr)) {
            return Optional.empty();
        }

        JcaBaseAlgorithmMapper algorithmMapper = new JcaBaseAlgorithmMapper();
        Optional<Algorithm> algorithm =
                algorithmMapper.parse(algorithmStr, detectionLocation, configuration);
        if (algorithm.isEmpty()) {
            return Optional.empty();
        }

        // Authenticated Encryption check
        if (modeOptional.isPresent()) {
            Mode mode = modeOptional.get();
            if (mode.getName().toLowerCase().contains("gcm")
                    || mode.getName().toLowerCase().contains("ccm")) {
                return Optional.of(
                        new AuthenticatedEncryption(
                                algorithm.get(),
                                mode,
                                paddingOptional.orElse(null),
                                null,
                                detectionLocation));
            }
        }

        if (algorithmStr.contains("RSA") && (modeOptional.isEmpty() || paddingOptional.isEmpty())) {
            // not a cipher
            return Optional.empty();
        }

        if (isBlockCipher(algorithmStr)) {
            BlockCipher cipher =
                    new BlockCipher(
                            algorithm.get(),
                            modeOptional.orElse(null),
                            paddingOptional.orElse(null),
                            detectionLocation);
            return Optional.of(cipher);
        } else if (isStreamCipher(algorithmStr)) {
            StreamCipher cipher =
                    new StreamCipher(
                            algorithm.get(),
                            modeOptional.orElse(null),
                            paddingOptional.orElse(null),
                            detectionLocation);
            return Optional.of(cipher);
        } else if (algorithmStr.equalsIgnoreCase("RSA")) {
            final Algorithm rsa = algorithm.get();
            modeOptional.ifPresent(rsa::append);
            paddingOptional.ifPresent(rsa::append);
            return algorithm;
        }

        return Optional.empty();
    }

    private boolean reflectValidValues(@Nonnull final String str) {
        return isBlockCipher(str) || isStreamCipher(str) || str.equalsIgnoreCase("RSA");
    }

    private boolean isBlockCipher(@Nonnull final String str) {
        return blockCiphers.stream().anyMatch(str::equalsIgnoreCase);
    }

    private boolean isStreamCipher(@Nonnull final String str) {
        return streamCiphers.stream().anyMatch(str::equalsIgnoreCase);
    }
}
