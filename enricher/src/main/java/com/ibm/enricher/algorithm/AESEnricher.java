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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
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

    @NotNull @Override
    public INode enrich(@NotNull INode node) {
        if (node instanceof AES aes) {
            return enrich(aes);
        }
        return node;
    }

    @Nonnull
    private INode enrich(@NotNull AES aes) {
        @Nullable KeyLength keyLength = aes.getKeyLength().orElse(null);
        @Nullable final Mode mode = aes.getMode().orElse(null);
        // default key length
        if (keyLength == null) {
           switch (aes.getDetectionContext().bundle().getIdentifier()) {
               case "Jca": {
                   keyLength = new KeyLength(128, aes.getDetectionContext());
                   aes.append(keyLength);
               }
           }
        }
        // add oid
        final Oid oid = new Oid(buildOid(keyLength, mode), aes.getDetectionContext());
        aes.append(oid);

        // authenticated encryption
        if (mode instanceof GCM || mode instanceof CCM) {
            return new AES(AuthenticatedEncryption.class, aes);
        }
        return aes;
    }

    @Nonnull
    private String buildOid(@Nullable KeyLength keyLength, @Nullable Mode mode) {
        StringBuilder builder = new StringBuilder(BASE_OID);
        if (keyLength == null) {
            return BASE_OID;
        }
        Integer keySizeOidNumber = KEYSIZE_OID_MAP.get(keyLength.getValue());
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
