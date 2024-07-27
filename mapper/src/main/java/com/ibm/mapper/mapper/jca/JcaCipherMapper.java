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
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.algorithm.AES;
import com.ibm.mapper.model.algorithm.AESWrap;
import com.ibm.mapper.model.algorithm.Blowfish;
import com.ibm.mapper.model.algorithm.ChaCha20;
import com.ibm.mapper.model.algorithm.DES;
import com.ibm.mapper.model.algorithm.DESede;
import com.ibm.mapper.model.algorithm.DESedeWrap;
import com.ibm.mapper.model.algorithm.Poly1305;
import com.ibm.mapper.model.algorithm.RC2;
import com.ibm.mapper.model.algorithm.RC4;
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
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
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

                // padding
                String paddingStr = rest.substring(slashIndex + 1);
            }
        } else {
            algorithmStr = str;
        }

        if (algorithmStr.contains("_")) {
            int index = algorithmStr.indexOf("_");
            String keyStr = algorithmStr.substring(index + 1);
            algorithmStr = algorithmStr.substring(0, index);

            Integer size = Integer.parseInt(keyStr);
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
                                algorithm.get(), mode, paddingOptional.orElse(null), null));
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
                            paddingOptional.orElse(null));
            return Optional.of(cipher);
        } else if (isStreamCipher(algorithmStr)) {
            StreamCipher cipher =
                    new StreamCipher(
                            algorithm.get(),
                            modeOptional.orElse(null),
                            paddingOptional.orElse(null));
            return Optional.of(cipher);
        } else if (algorithmStr.equalsIgnoreCase("RSA")) {
            final Algorithm rsa = algorithm.get();
            modeOptional.ifPresent(rsa::append);
            paddingOptional.ifPresent(rsa::append);
            return algorithm;
        }

        return Optional.empty();
    }

    @Nonnull
    private Optional<? extends Cipher> map(
            @Nonnull String cipherAlgorithm, @Nonnull DetectionLocation detectionLocation) {
        return switch (cipherAlgorithm.toUpperCase().trim()) {
            case "AES" -> Optional.of(new AES(detectionLocation));
            case "AES_128" ->
                    Optional.of(new AES(new DigestSize(128, detectionLocation), detectionLocation));
            case "AES_192" ->
                    Optional.of(new AES(new DigestSize(192, detectionLocation), detectionLocation));
            case "AES_256" ->
                    Optional.of(new AES(new DigestSize(256, detectionLocation), detectionLocation));

            case "AESWRAP" -> Optional.of(new AESWrap(detectionLocation));
            case "AESWRAP_128" ->
                    Optional.of(
                            new AESWrap(new DigestSize(128, detectionLocation), detectionLocation));
            case "AESWRAP_192" ->
                    Optional.of(
                            new AESWrap(new DigestSize(192, detectionLocation), detectionLocation));
            case "AESWRAP_256" ->
                    Optional.of(
                            new AESWrap(new DigestSize(256, detectionLocation), detectionLocation));

            case "RC4", "ARCFOUR", "ARC4" -> Optional.of(new RC4(detectionLocation));
            case "RC2", "ARC2" -> Optional.of(new RC2(detectionLocation));
            case "BLOWFISH" -> Optional.of(new Blowfish(detectionLocation));
            case "DES" -> Optional.of(new DES(detectionLocation));
            case "DESEDE", "TRIPLEDES" -> Optional.of(new DESede(detectionLocation));
            case "DESEDEWRAP", "TRIPLEDESWRAP" -> Optional.of(new DESedeWrap(detectionLocation));
            case "CHACHA20" -> Optional.of(new ChaCha20(detectionLocation));
            case "CHACHA20-POLY1305" -> {
                final ChaCha20 chaCha20 = new ChaCha20(detectionLocation);
                chaCha20.append(new Poly1305(detectionLocation));
                yield Optional.of(chaCha20);
            }
            default -> Optional.empty();
        };
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
