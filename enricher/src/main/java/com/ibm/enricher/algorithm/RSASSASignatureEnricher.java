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
package com.ibm.enricher.algorithm;

import com.ibm.enricher.utils.Utils;
import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.jca.JcaMGFMapper;
import com.ibm.mapper.mapper.jca.JcaMessageDigestMapper;
import com.ibm.mapper.model.*;
import java.util.Map;
import javax.annotation.Nonnull;

public class RSASSASignatureEnricher implements ISignatureEnricher {

    @Override
    public void enrich(
            @Nonnull Signature signature,
            @Nonnull Map<Class<? extends INode>, INode> dependingNodes) {
        MessageDigest messageDigest = (MessageDigest) dependingNodes.get(MessageDigest.class);
        if (messageDigest == null) {
            // default
            final Oid oid = new Oid("1.2.840.113549.1.1.10", signature.getDetectionContext());
            signature.append(oid);
        } else {
            final String messageDigestName = Utils.sanitiseAlgorithmName(messageDigest.asString());
            switch (messageDigestName) {
                case "SHA3-224" -> {
                    final Oid oid =
                            new Oid("2.16.840.1.101.3.4.3.13", messageDigest.getDetectionContext());
                    signature.append(oid);
                }
                case "SHA3-256" -> {
                    final Oid oid =
                            new Oid("2.16.840.1.101.3.4.3.14", messageDigest.getDetectionContext());
                    signature.append(oid);
                }
                case "SHA3-384" -> {
                    final Oid oid =
                            new Oid("2.16.840.1.101.3.4.3.15", messageDigest.getDetectionContext());
                    signature.append(oid);
                }
                case "SHA3-512" -> {
                    final Oid oid =
                            new Oid("2.16.840.1.101.3.4.3.16", messageDigest.getDetectionContext());
                    signature.append(oid);
                }
                default -> {
                    final Oid oid =
                            new Oid("1.2.840.113549.1.1.10", signature.getDetectionContext());
                    signature.append(oid);
                }
            }
        }
        /* Note: the PSSParameterSpec.DEFAULT uses the following:
         *  message digest -- "SHA-1"
         *  mask generation function (mgf) -- "MGF1"
         *  parameters for mgf -- MGF1ParameterSpec.SHA1
         *  SaltLength -- 20 byte
         *  TrailerField -- 1
         */
        if (signature.hasChildOfType(MessageDigest.class).isEmpty()) {
            new JcaMessageDigestMapper()
                    .parse("SHA-1", signature.getDetectionContext(), Configuration.DEFAULT)
                    .ifPresent(signature::append);
        }
        if (signature.hasChildOfType(MaskGenerationFunction.class).isEmpty()) {
            new JcaMGFMapper()
                    .parse("MGF1", signature.getDetectionContext(), Configuration.DEFAULT)
                    .map(
                            mgf -> {
                                new JcaMessageDigestMapper()
                                        .parse(
                                                "SHA-1",
                                                signature.getDetectionContext(),
                                                Configuration.DEFAULT)
                                        .ifPresent(mgf::append);
                                return mgf;
                            })
                    .ifPresent(signature::append);
        }
        if (signature.hasChildOfType(SaltLength.class).isEmpty()) {
            signature.append(new SaltLength(160, signature.getDetectionContext()));
        }
    }
}
