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
import com.ibm.mapper.model.Cipher;
import com.ibm.mapper.model.HMAC;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Optional;

public class JcaPasswordBasedEncryptionMapper implements IMapper {

    public JcaPasswordBasedEncryptionMapper() {
        // nothing
    }

    @Nonnull
    @Override
    public Optional<PasswordBasedEncryption> parse(
            @Nullable final String str,
            @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        final String generalizedStr = str.toLowerCase().trim();
        if (!generalizedStr.contains("pbewith")) {
            return Optional.empty();
        }

        String hmacOrDigestStr;
        String cipherStr = null;
        int algoStartIndex = generalizedStr.indexOf("pbewith") + 7;
        if (generalizedStr.contains("and")) {
            int encIndex = generalizedStr.indexOf("and") + 3;
            cipherStr = str.substring(encIndex);
            hmacOrDigestStr = str.substring(algoStartIndex, generalizedStr.indexOf("and"));
        } else {
            hmacOrDigestStr = str.substring(algoStartIndex);
        }

        // cipher
        Optional<? extends Cipher> cipher = Optional.empty();
        if (cipherStr != null) {
            JcaCipherMapper cipherMapper = new JcaCipherMapper();
            cipher = cipherMapper.parse(cipherStr, detectionLocation);
        }

        // hmac
        JcaMacMapper macMapper = new JcaMacMapper();
        Optional<HMAC> macOptional =
                macMapper.parse(hmacOrDigestStr, detectionLocation);
        if (macOptional.isPresent()) {
            // heck for cipher
            return Optional.of(cipher.map(c -> new PasswordBasedEncryption(macOptional.get(), c))
                    .orElse(new PasswordBasedEncryption(macOptional.get())));
        }

        // digest
        JcaMessageDigestMapper messageDigestMapper = new JcaMessageDigestMapper();
        Optional<MessageDigest> messageDigestOptional =
                messageDigestMapper.parse(hmacOrDigestStr, detectionLocation);
        if (messageDigestOptional.isPresent()) {
            return cipher.map(c -> new PasswordBasedEncryption(messageDigestOptional.get(), c));
        }

        return Optional.empty();
    }
}
