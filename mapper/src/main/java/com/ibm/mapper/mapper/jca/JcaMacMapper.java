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
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaMacMapper implements IMapper {
    private static final List<String> validValues =
            List.of(
                    "HmacMD5",
                    "HmacSHA1",
                    "HmacSHA224",
                    "HmacSHA256",
                    "HmacSHA384",
                    "HmacSHA512",
                    "HmacSHA512/224",
                    "HmacSHA512/256",
                    "HmacSHA3-224",
                    "HmacSHA3-256",
                    "HmacSHA3-384",
                    "HmacSHA3-512");

    @Nonnull
    @Override
    public Optional<Algorithm> parse(
            @Nullable final String str,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull final Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }

        // check if it is pbe
        JcaPasswordBasedEncryptionMapper pbeMapper = new JcaPasswordBasedEncryptionMapper();
        Optional<PasswordBasedEncryption> pbeOptional =
                pbeMapper.parse(str, detectionLocation, configuration);
        if (pbeOptional.isPresent()) {
            return JcaBaseAlgorithmMapper.generalizeAlgorithm(pbeOptional);
        }

        if (!reflectValidValues(str)) {
            return Optional.empty();
        }

        final String generalizedStr = str.toLowerCase().trim();
        int hashAlgoPos = generalizedStr.indexOf("Hmac".toLowerCase()) + 4;
        String messageDigest = str.substring(hashAlgoPos).replace("-", "");

        // mac
        JcaBaseAlgorithmMapper algorithmMapper = new JcaBaseAlgorithmMapper();
        Optional<Algorithm> algorithm =
                algorithmMapper.parse(str, detectionLocation, configuration);
        if (algorithm.isEmpty()) {
            return Optional.empty();
        }
        Mac mac = new Mac(algorithm.get());

        JcaMessageDigestMapper jcaMessageDigestMapper = new JcaMessageDigestMapper();
        Optional<MessageDigest> messageDigestOptional =
                jcaMessageDigestMapper.parse(messageDigest, detectionLocation, configuration);
        messageDigestOptional.ifPresent(mac::append);
        mac.apply(configuration);
        return Optional.of(mac);
    }

    private boolean reflectValidValues(@Nonnull final String str) {
        return validValues.stream().anyMatch(str::equalsIgnoreCase);
    }
}
