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
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.OutputFormat;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.Ed25519;
import com.ibm.mapper.model.algorithms.Ed448;
import com.ibm.mapper.model.algorithms.EdDSA;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaSignatureMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<Signature> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        final String generalizedStr = str.toLowerCase().trim();
        if (!generalizedStr.contains("with")) {
            return map(str, detectionLocation);
        }

        int hashEndPos = generalizedStr.indexOf("with");
        String digestStr = str.substring(0, hashEndPos);
        JcaMessageDigestMapper jcaMessageDigestMapper = new JcaMessageDigestMapper();
        final Optional<MessageDigest> messageDigestOptional =
                jcaMessageDigestMapper.parse(digestStr, detectionLocation);

        int encryptStartPos = hashEndPos + 4;
        String signatureStr = str.substring(encryptStartPos);
        final String format;
        if (generalizedStr.contains("in") && generalizedStr.contains("format")) {
            int inStartPos = generalizedStr.indexOf("in");
            int inEndPos = inStartPos + 2;
            signatureStr = str.substring(encryptStartPos, inStartPos);
            format = str.substring(inEndPos);
        } else {
            format = null;
        }

        return map(signatureStr, detectionLocation)
                .map(
                        signature -> {
                            messageDigestOptional.ifPresent(signature::put);
                            if (format != null) {
                                signature.put(new OutputFormat(format, detectionLocation));
                            }
                            return signature;
                        });
    }

    @Nonnull
    private Optional<Signature> map(
            @Nonnull String signature, @Nonnull DetectionLocation detectionLocation) {
        return switch (signature.toUpperCase().trim()) {
            case "ED25519" -> Optional.of(new Ed25519(detectionLocation));
            case "ED448" -> Optional.of(new Ed448(detectionLocation));
            case "EDDSA" -> Optional.of(new EdDSA(detectionLocation));
            case "RSASSA-PSS" -> Optional.of(new RSAssaPSS(detectionLocation));
            case "ECDSA" -> Optional.of(new ECDSA(detectionLocation));
            case "DSA" -> Optional.of(new DSA(detectionLocation));
            case "RSA" -> Optional.of(new RSA(Signature.class, detectionLocation));
            default -> Optional.empty();
        };
    }
}
