/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2025 IBM
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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.HMAC;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import javax.annotation.Nonnull;

public class HMACEnricher implements IEnricher {

    @Nonnull
    @Override
    public INode enrich(@Nonnull INode node) {
        if (node instanceof HMAC hmac) {
            hmac.hasChildOfType(MessageDigest.class)
                    .ifPresent(
                            digest -> {
                                if (digest instanceof SHA) {
                                    hmac.put(
                                            new Oid(
                                                    "1.2.840.113549.2.7",
                                                    hmac.getDetectionContext()));
                                } else if (digest instanceof SHA2 sha2) {
                                    sha2.getDigestSize()
                                            .ifPresent(
                                                    digestSize -> {
                                                        switch (digestSize.getValue()) {
                                                            case 224 ->
                                                                    hmac.put(
                                                                            new Oid(
                                                                                    "1.2.840.113549.2.8",
                                                                                    hmac
                                                                                            .getDetectionContext()));
                                                            case 256 ->
                                                                    hmac.put(
                                                                            new Oid(
                                                                                    "1.2.840.113549.2.9",
                                                                                    hmac
                                                                                            .getDetectionContext()));
                                                            case 384 ->
                                                                    hmac.put(
                                                                            new Oid(
                                                                                    "1.2.840.113549.2.10",
                                                                                    hmac
                                                                                            .getDetectionContext()));
                                                            case 512 ->
                                                                    hmac.put(
                                                                            new Oid(
                                                                                    "1.2.840.113549.2.11",
                                                                                    hmac
                                                                                            .getDetectionContext()));
                                                        }
                                                    });
                                } else if (digest instanceof SHA3 sha3) {
                                    sha3.getDigestSize()
                                            .ifPresent(
                                                    digestSize -> {
                                                        switch (digestSize.getValue()) {
                                                            case 224 ->
                                                                    hmac.put(
                                                                            new Oid(
                                                                                    "2.16.840.1.101.3.4.2.13",
                                                                                    hmac
                                                                                            .getDetectionContext()));
                                                            case 256 ->
                                                                    hmac.put(
                                                                            new Oid(
                                                                                    "2.16.840.1.101.3.4.2.14",
                                                                                    hmac
                                                                                            .getDetectionContext()));
                                                            case 384 ->
                                                                    hmac.put(
                                                                            new Oid(
                                                                                    "2.16.840.1.101.3.4.2.15",
                                                                                    hmac
                                                                                            .getDetectionContext()));
                                                            case 512 ->
                                                                    hmac.put(
                                                                            new Oid(
                                                                                    "2.16.840.1.101.3.4.2.16",
                                                                                    hmac
                                                                                            .getDetectionContext()));
                                                        }
                                                    });
                                }
                            });
        }
        return node;
    }
}
