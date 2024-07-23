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
import java.util.*;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaOAEPPaddingMapper implements IMapper {
    @Nonnull
    @Override
    public Optional<OptimalAsymmetricEncryptionPadding> parse(
            @Nullable final String str,
            @Nonnull final DetectionLocation detectionLocation,
            @Nonnull final Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }

        if (!str.contains("OAEP")) {
            return Optional.empty();
        }

        Map<Class<? extends INode>, INode> assets = new HashMap<>();
        if (str.contains("OAEPWith")) {
            String digestStr;
            String mgfStr = null;

            final String generalizedStr = str.toLowerCase().trim();
            int algoStartIndex = generalizedStr.indexOf("OAEPWith".toLowerCase()) + 8;
            int paddingSuffix = generalizedStr.indexOf("Padding".toLowerCase());
            if (generalizedStr.contains("and")) {
                int encIndex = generalizedStr.indexOf("and") + 3;
                mgfStr = str.substring(encIndex, paddingSuffix);
                digestStr = str.substring(algoStartIndex, generalizedStr.indexOf("and"));
            } else {
                digestStr = str.substring(algoStartIndex, paddingSuffix);
            }

            // digest
            JcaMessageDigestMapper jcaMessageDigestMapper = new JcaMessageDigestMapper();
            Optional<MessageDigest> messageDigestOptional =
                    jcaMessageDigestMapper.parse(digestStr, detectionLocation, configuration);
            messageDigestOptional.ifPresent(digest -> assets.put(digest.getKind(), digest));
            // mgf
            if (mgfStr != null) {
                JcaMGFMapper jcaMGFMapper = new JcaMGFMapper();
                Optional<MaskGenerationFunction> mgfOptional =
                        jcaMGFMapper.parse(mgfStr, detectionLocation, configuration);
                mgfOptional.ifPresent(mgf -> assets.put(mgf.getKind(), mgf));
            }
        }

        JcaBasePaddingMapper jcaBasePaddingMapper = new JcaBasePaddingMapper();
        Optional<Padding> paddingOptional =
                jcaBasePaddingMapper.parseAndAddChildren(
                        str, detectionLocation, configuration, assets);
        if (paddingOptional.isEmpty()) {
            return Optional.empty();
        }
        OptimalAsymmetricEncryptionPadding oaepPadding =
                new OptimalAsymmetricEncryptionPadding(paddingOptional.get());
        return Optional.of(oaepPadding);
    }
}
