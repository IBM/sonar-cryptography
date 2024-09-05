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
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaOAEPPaddingMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<OAEP> parse(
            @Nullable final String str, @Nonnull final DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        if (!str.contains("OAEP")) {
            return Optional.empty();
        }

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
            final JcaMessageDigestMapper jcaMessageDigestMapper = new JcaMessageDigestMapper();
            Optional<MessageDigest> messageDigestOptional =
                    jcaMessageDigestMapper.parse(digestStr, detectionLocation);

            // mgf
            Optional<MaskGenerationFunction> mgfOptional = Optional.empty();
            if (mgfStr != null) {
                final JcaMGFMapper jcaMGFMapper = new JcaMGFMapper();
                mgfOptional = jcaMGFMapper.parse(mgfStr, detectionLocation);
            }

            if (messageDigestOptional.isPresent()) {
                return mgfOptional
                        .map(
                                maskGenerationFunction ->
                                        new OAEP(
                                                messageDigestOptional.get(),
                                                maskGenerationFunction))
                        .or(
                                () ->
                                        Optional.of(
                                                new OAEP(
                                                        messageDigestOptional.get(),
                                                        detectionLocation)));
            }
        }

        return Optional.of(new OAEP(detectionLocation));
    }
}
