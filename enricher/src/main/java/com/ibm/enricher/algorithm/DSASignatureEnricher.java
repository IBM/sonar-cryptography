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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Signature;
import java.util.Map;
import javax.annotation.Nonnull;

public class DSASignatureEnricher implements ISignatureEnricher {

    @Override
    public void enrich(
            @Nonnull Signature signature,
            @Nonnull Map<Class<? extends INode>, INode> dependingNodes) {
        MessageDigest messageDigest = (MessageDigest) dependingNodes.get(MessageDigest.class);
        if (messageDigest == null) {
            return;
        }

        final String messageDigestName = Utils.sanitiseAlgorithmName(messageDigest.asString());
        switch (messageDigestName) {
            case "SHA1" -> {
                final Oid oid = new Oid("1.3.14.3.2.27", messageDigest.getDetectionContext());
                signature.append(oid);
            }
            case "SHA224" -> {
                final Oid oid =
                        new Oid("2.16.840.1.101.3.4.3.1", messageDigest.getDetectionContext());
                signature.append(oid);
            }
            case "SHA256" -> {
                final Oid oid =
                        new Oid("2.16.840.1.101.3.4.3.2", messageDigest.getDetectionContext());
                signature.append(oid);
            }
            case "SHA384" -> {
                final Oid oid =
                        new Oid("2.16.840.1.101.3.4.3.3", messageDigest.getDetectionContext());
                signature.append(oid);
            }
            case "SHA512" -> {
                final Oid oid =
                        new Oid("2.16.840.1.101.3.4.3.4", messageDigest.getDetectionContext());
                signature.append(oid);
            }
            case "SHA3-224" -> {
                final Oid oid =
                        new Oid("2.16.840.1.101.3.4.3.5", messageDigest.getDetectionContext());
                signature.append(oid);
            }
            case "SHA3-256" -> {
                final Oid oid =
                        new Oid("2.16.840.1.101.3.4.3.6", messageDigest.getDetectionContext());
                signature.append(oid);
            }
            case "SHA3-384" -> {
                final Oid oid =
                        new Oid("2.16.840.1.101.3.4.3.7", messageDigest.getDetectionContext());
                signature.append(oid);
            }
            case "SHA3-512" -> {
                final Oid oid =
                        new Oid("2.16.840.1.101.3.4.3.8", messageDigest.getDetectionContext());
                signature.append(oid);
            }
            default -> {
                // nothing
            }
        }
    }
}
