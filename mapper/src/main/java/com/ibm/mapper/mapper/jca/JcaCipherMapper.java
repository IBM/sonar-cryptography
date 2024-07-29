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
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.AESWrap;
import com.ibm.mapper.model.algorithms.Blowfish;
import com.ibm.mapper.model.algorithms.ChaCha20;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.DESedeWrap;
import com.ibm.mapper.model.algorithms.Poly1305;
import com.ibm.mapper.model.algorithms.RC2;
import com.ibm.mapper.model.algorithms.RC4;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Optional;

public class JcaCipherMapper implements IMapper {

    public JcaCipherMapper() {
        // nothing
    }

    @Nonnull
    @Override
    public Optional<? extends Algorithm> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        String algorithmStr;
        Optional<Mode> modeOptional = Optional.empty();
        Optional<? extends Padding> paddingOptional = Optional.empty();
        if (str.contains("/")) {
            int slashIndex = str.indexOf("/");
            algorithmStr = str.substring(0, slashIndex);

            String rest = str.substring(slashIndex + 1);
            if (rest.contains("/")) {
                slashIndex = rest.indexOf("/");
                // mode
                final String modeStr = rest.substring(0, slashIndex);
                final JcaModeMapper jcaModeMapper = new JcaModeMapper();
                modeOptional = jcaModeMapper.parse(modeStr, detectionLocation);
                // padding
                String paddingStr = rest.substring(slashIndex + 1);
                final JcaPaddingMapper jcaPaddingMapper = new JcaPaddingMapper();
                paddingOptional = jcaPaddingMapper.parse(paddingStr, detectionLocation);
            }
        } else {
            algorithmStr = str;
        }

        // check if it is pbe
        JcaPasswordBasedEncryptionMapper pbeMapper = new JcaPasswordBasedEncryptionMapper();
        Optional<PasswordBasedEncryption> pbeOptional =
                pbeMapper.parse(algorithmStr, detectionLocation);
        if (pbeOptional.isPresent()) {
            // pbe
            return pbeOptional;
        }

        Optional<? extends Cipher> possibleCipher = map(algorithmStr, detectionLocation);
        if (possibleCipher.isEmpty()) {
            return Optional.empty();
        }
        final Cipher cipher = possibleCipher.get();

        // Authenticated Encryption check
        if (modeOptional.isPresent()) {
            final Mode mode = modeOptional.get();
            if (mode instanceof GCM || mode instanceof CCM) {
                return paddingOptional
                        .map(padding -> new AuthenticatedEncryption(cipher, mode, padding))
                        .or(() -> Optional.of(new AuthenticatedEncryption(cipher, mode)));
            }
        }

        modeOptional.ifPresent(cipher::append);
        paddingOptional.ifPresent(cipher::append);
        return Optional.of(cipher);
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
            case "RSA" -> Optional.of(new RSA(detectionLocation)).map(Cipher::new);
            default -> Optional.empty();
        };
    }
}
