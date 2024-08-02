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

import com.ibm.enricher.IEnricher;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.GCM;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;

public class AESEnricher implements IEnricher {
    private static final String BASE_OID = "2.16.840.1.101.3.4.1";

    private static final Map<String, Integer> MODE_OID_MAP =
            Map.of(
                    "ecb", 1,
                    "cbc", 2,
                    "ofb", 3,
                    "cfb", 4,
                    "wrap", 5,
                    "gcm", 6,
                    "ccm", 7,
                    "wrap-pad", 8);

    private static final Map<Integer, Integer> KEYSIZE_OID_MAP =
            Map.of(
                    192, 2,
                    256, 4);

    @Override
    public void enrich(@NotNull INode node) {
        if (node instanceof AES aes) {
            enrich(aes);
        }
    }

    private void enrich(@NotNull AES aes) {
        @Nullable final DigestSize digestSize = aes.getDigestSize().orElse(null);
        @Nullable final Mode mode = aes.getMode().orElse(null);
        // add oid
        final Oid oid = new Oid(buildOid(digestSize, mode), aes.getDetectionContext());
        aes.append(oid);
        // block size
        aes.append(new BlockSize(128, aes.getDetectionContext()));
        // authenticated encryption
        if (mode instanceof GCM || mode instanceof CCM) {
            final AES aeAES = new AES(AuthenticatedEncryption.class, aes);
        }
    }

    @Nonnull
    private String buildOid(@Nullable DigestSize digestSize, @Nullable Mode mode) {
        StringBuilder builder = new StringBuilder(BASE_OID);
        if (digestSize == null) {
            return BASE_OID;
        }
        Integer keySizeOidNumber = KEYSIZE_OID_MAP.get(digestSize.getValue());
        if (keySizeOidNumber != null) {
            builder.append(".").append(keySizeOidNumber);
        }

        if (mode == null) {
            return builder.toString();
        }
        Integer modeOidNumber = MODE_OID_MAP.get(mode.asString().toLowerCase());
        if (modeOidNumber != null) {
            if (keySizeOidNumber == null) {
                builder.append(".");
            }
            builder.append(modeOidNumber);
        }
        return builder.toString();
    }
}
