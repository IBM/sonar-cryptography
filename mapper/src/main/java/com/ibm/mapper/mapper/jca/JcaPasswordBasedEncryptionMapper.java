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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaPasswordBasedEncryptionMapper implements IMapper {

    public JcaPasswordBasedEncryptionMapper() {
        // nothing
    }

    @Nonnull
    @Override
    public Optional<PasswordBasedEncryption> parse(
            @Nullable final String str,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull final Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }

        final String generalizedStr = str.toLowerCase().trim();
        if (!generalizedStr.contains("pbewith")) {
            return Optional.empty();
        }

        String prfOrDigestStr;
        String encryptionStr = null;
        int algoStartIndex = generalizedStr.indexOf("pbewith") + 7;
        if (generalizedStr.contains("and")) {
            int encIndex = generalizedStr.indexOf("and") + 3;
            encryptionStr = str.substring(encIndex);
            prfOrDigestStr = str.substring(algoStartIndex, generalizedStr.indexOf("and"));
        } else {
            prfOrDigestStr = str.substring(algoStartIndex);
        }



        JcaBaseAlgorithmMapper jcaBaseAlgorithmMapper = new JcaBaseAlgorithmMapper();
        Map<Class<? extends INode>, INode> assets = new HashMap<>();
        // pseudo random function
        JcaMacMapper macMapper = new JcaMacMapper();
        Optional<Algorithm> macOptional =
                macMapper.parse(prfOrDigestStr, detectionLocation, configuration);
        macOptional.ifPresent(mac -> assets.put(mac.getKind(), mac));

        JcaMessageDigestMapper messageDigestMapper = new JcaMessageDigestMapper();
        Optional<MessageDigest> messageDigestOptional =
                messageDigestMapper.parse(prfOrDigestStr, detectionLocation, configuration);
        messageDigestOptional.ifPresent(digest -> assets.put(digest.getKind(), digest));

        // encryption
        if (encryptionStr != null) {
            Optional<Algorithm> encryptionOptional =
                    jcaBaseAlgorithmMapper.parse(encryptionStr, detectionLocation, configuration);
            encryptionOptional.ifPresent(
                    encryption -> assets.put(encryption.getKind(), encryption));
        }

        Optional<Algorithm> algorithmOptional =
                jcaBaseAlgorithmMapper.parseAndAddChildren(
                        str, detectionLocation, configuration, assets);
        if (algorithmOptional.isEmpty()) {
            return Optional.empty();
        }

        PasswordBasedEncryption pbe = new PasswordBasedEncryption(algorithmOptional.get());
        return Optional.of(pbe);
    }
}
