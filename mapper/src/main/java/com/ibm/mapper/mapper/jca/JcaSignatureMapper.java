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
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaSignatureMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<Signature> parse(
            @Nullable String str,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }

        final String generalizedStr = str.toLowerCase().trim();
        if (!generalizedStr.contains("with")) {
            if (!generalizedStr.equalsIgnoreCase("RSASSA-PSS")) {
                return Optional.empty();
            }
            final Algorithm algorithm = new Algorithm("RSASSA-PSS", detectionLocation);
            final Signature signature = new Signature(algorithm, detectionLocation);
            final ProbabilisticSignatureScheme probabilisticSignatureScheme =
                    new ProbabilisticSignatureScheme(detectionLocation);
            signature.append(probabilisticSignatureScheme);

            final JcaBaseAlgorithmMapper jcaBaseAlgorithmMapper = new JcaBaseAlgorithmMapper();
            jcaBaseAlgorithmMapper
                    .parse("RSA", detectionLocation, configuration)
                    .ifPresent(signature::append);

            return Optional.of(signature);
        }

        Map<Class<? extends INode>, INode> assets = new HashMap<>();
        int hashEndPos = generalizedStr.indexOf("with");
        String digestStr = str.substring(0, hashEndPos);
        JcaMessageDigestMapper jcaMessageDigestMapper = new JcaMessageDigestMapper();
        Optional<MessageDigest> messageDigestOptional =
                jcaMessageDigestMapper.parse(digestStr, detectionLocation, configuration);
        messageDigestOptional.ifPresent(digest -> assets.put(digest.getKind(), digest));

        int encryptStartPos = hashEndPos + 4;
        String signatureStr = str.substring(encryptStartPos);
        String mgf = null;
        String format = null;

        if (generalizedStr.contains("and")) {
            int andStartPos = generalizedStr.indexOf("and");
            int andEndPos = andStartPos + 3;
            signatureStr = str.substring(encryptStartPos, andStartPos);
            if (generalizedStr.contains("in") && generalizedStr.contains("format")) {
                int inStartPos = generalizedStr.indexOf("in");
                int inEndPos = inStartPos + 2;
                mgf = str.substring(andEndPos, inStartPos);
                format = str.substring(inEndPos);
            } else {
                mgf = str.substring(andEndPos);
            }
        } else if (generalizedStr.contains("in") && generalizedStr.contains("format")) {
            int inStartPos = generalizedStr.indexOf("in");
            int inEndPos = inStartPos + 2;
            signatureStr = str.substring(encryptStartPos, inStartPos);
            format = str.substring(inEndPos);
        }

        if (mgf != null) {
            final JcaMGFMapper jcaMGFMapper = new JcaMGFMapper();
            Optional<MaskGenerationFunction> mgfOptional =
                    jcaMGFMapper.parse(mgf, detectionLocation, configuration);
            mgfOptional.ifPresent(
                    maskGenerationFunction ->
                            assets.put(maskGenerationFunction.getKind(), maskGenerationFunction));
        }

        final JcaBaseAlgorithmMapper jcaBaseAlgorithmMapper = new JcaBaseAlgorithmMapper();
        Optional<Algorithm> signatureOptional =
                jcaBaseAlgorithmMapper.parse(signatureStr, detectionLocation, configuration);
        signatureOptional.ifPresent(signature -> assets.put(signature.getKind(), signature));

        // generate Signature
        Optional<Algorithm> singatureAlgorithmOptional =
                jcaBaseAlgorithmMapper.parseAndAddChildren(
                        str, detectionLocation, configuration, assets);
        if (singatureAlgorithmOptional.isEmpty()) {
            return Optional.empty();
        }

        Signature signature = new Signature(singatureAlgorithmOptional.get(), detectionLocation);
        if (format != null) {
            OutputFormat outputFormat = new OutputFormat(format, detectionLocation);
            outputFormat.apply(configuration);
            signature.append(outputFormat);
        }

        return Optional.of(signature);
    }
}
