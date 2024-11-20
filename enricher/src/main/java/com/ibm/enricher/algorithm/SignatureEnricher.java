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
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.ECDSA;
import com.ibm.mapper.model.algorithms.MD2;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import java.util.Optional;
import javax.annotation.Nonnull;

public class SignatureEnricher implements IEnricher {

    @Override
    public @Nonnull INode enrich(@Nonnull INode node) {
        if (node.is(Signature.class)) {
            if (node instanceof DSA dsa) {
                return enrichDSA(dsa);
            }
            if (node instanceof ECDSA ecdsa) {
                return enrichECDSA(ecdsa);
            }
            if (node instanceof RSA rsa) {
                return enrichRSA(rsa);
            }
        }
        return node;
    }

    @SuppressWarnings("java:S3776")
    @Nonnull
    private Signature enrichRSA(@Nonnull RSA rsa) {
        Optional<INode> possibleDigest = rsa.hasChildOfType(MessageDigest.class);
        if (possibleDigest.isEmpty()) {
            return rsa;
        }

        final INode digest = possibleDigest.get();
        if (digest instanceof MD2) {
            rsa.put(new Oid("1.2.840.113549.1.1.2", rsa.getDetectionContext()));
        } else if (digest instanceof MD5) {
            rsa.put(new Oid("1.2.840.113549.1.1.4", rsa.getDetectionContext()));
        } else if (digest instanceof SHA) {
            rsa.put(new Oid("1.2.840.113549.1.1.5", rsa.getDetectionContext()));
        } else if (digest instanceof SHA2 sha2) {
            sha2.getDigestSize()
                    .ifPresent(
                            digestSize -> {
                                switch (digestSize.getValue()) {
                                    case 224 ->
                                            sha2.hasChildOfType(MessageDigest.class)
                                                    .ifPresentOrElse(
                                                            messageDigest -> {
                                                                if (messageDigest
                                                                        instanceof SHA2 preHash) {
                                                                    preHash.getDigestSize()
                                                                            .map(
                                                                                    DigestSize
                                                                                            ::getValue)
                                                                            .filter(
                                                                                    size ->
                                                                                            size
                                                                                                    == 512)
                                                                            .ifPresent(
                                                                                    size ->
                                                                                            rsa.put(
                                                                                                    new Oid(
                                                                                                            "1.2.840.113549.1.1.15",
                                                                                                            rsa
                                                                                                                    .getDetectionContext())));
                                                                }
                                                            },
                                                            () ->
                                                                    rsa.put(
                                                                            new Oid(
                                                                                    "1.2.840.113549.1.1.14",
                                                                                    rsa
                                                                                            .getDetectionContext())));
                                    case 256 ->
                                            sha2.hasChildOfType(MessageDigest.class)
                                                    .ifPresentOrElse(
                                                            messageDigest -> {
                                                                if (messageDigest
                                                                        instanceof SHA2 preHash) {
                                                                    preHash.getDigestSize()
                                                                            .map(
                                                                                    DigestSize
                                                                                            ::getValue)
                                                                            .filter(
                                                                                    size ->
                                                                                            size
                                                                                                    == 512)
                                                                            .ifPresent(
                                                                                    size ->
                                                                                            rsa.put(
                                                                                                    new Oid(
                                                                                                            "1.2.840.113549.1.1.15",
                                                                                                            rsa
                                                                                                                    .getDetectionContext())));
                                                                }
                                                            },
                                                            () ->
                                                                    rsa.put(
                                                                            new Oid(
                                                                                    "1.2.840.113549.1.1.11",
                                                                                    rsa
                                                                                            .getDetectionContext())));
                                    case 384 ->
                                            rsa.put(
                                                    new Oid(
                                                            "1.2.840.113549.1.1.12",
                                                            rsa.getDetectionContext()));
                                    case 512 ->
                                            rsa.put(
                                                    new Oid(
                                                            "1.2.840.113549.1.1.13",
                                                            rsa.getDetectionContext()));
                                    default -> {
                                        // nothing
                                    }
                                }
                            });
        } else if (digest instanceof SHA3 sha3) {
            sha3.getDigestSize()
                    .ifPresent(
                            digestSize -> {
                                switch (digestSize.getValue()) {
                                    case 224 ->
                                            rsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.13",
                                                            rsa.getDetectionContext()));
                                    case 256 ->
                                            rsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.14",
                                                            rsa.getDetectionContext()));
                                    case 384 ->
                                            rsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.15",
                                                            rsa.getDetectionContext()));
                                    case 512 ->
                                            rsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.16",
                                                            rsa.getDetectionContext()));
                                    default -> {
                                        // nothing
                                    }
                                }
                            });
        }
        return rsa;
    }

    @Nonnull
    private Signature enrichECDSA(@Nonnull ECDSA ecdsa) {
        Optional<INode> possibleDigest = ecdsa.hasChildOfType(MessageDigest.class);
        if (possibleDigest.isEmpty()) {
            return ecdsa;
        }

        final INode digest = possibleDigest.get();
        if (digest instanceof SHA) {
            ecdsa.put(new Oid("1.2.840.10045.4.1", ecdsa.getDetectionContext()));
        } else if (digest instanceof SHA2 sha2) {
            sha2.getDigestSize()
                    .ifPresent(
                            digestSize -> {
                                switch (digestSize.getValue()) {
                                    case 224 ->
                                            ecdsa.put(
                                                    new Oid(
                                                            "1.2.840.10045.4.3.1",
                                                            ecdsa.getDetectionContext()));
                                    case 256 ->
                                            ecdsa.put(
                                                    new Oid(
                                                            "1.2.840.10045.4.3.2",
                                                            ecdsa.getDetectionContext()));
                                    case 384 ->
                                            ecdsa.put(
                                                    new Oid(
                                                            "1.2.840.10045.4.3.3",
                                                            ecdsa.getDetectionContext()));
                                    case 512 ->
                                            ecdsa.put(
                                                    new Oid(
                                                            "1.2.840.10045.4.3.4",
                                                            ecdsa.getDetectionContext()));
                                    default -> {
                                        // nothing
                                    }
                                }
                            });
        } else if (digest instanceof SHA3 sha3) {
            sha3.getDigestSize()
                    .ifPresent(
                            digestSize -> {
                                switch (digestSize.getValue()) {
                                    case 224 ->
                                            ecdsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.9",
                                                            ecdsa.getDetectionContext()));
                                    case 256 ->
                                            ecdsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.10",
                                                            ecdsa.getDetectionContext()));
                                    case 384 ->
                                            ecdsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.11",
                                                            ecdsa.getDetectionContext()));
                                    case 512 ->
                                            ecdsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.12",
                                                            ecdsa.getDetectionContext()));
                                    default -> {
                                        // nothing
                                    }
                                }
                            });
        }
        return ecdsa;
    }

    @Nonnull
    private Signature enrichDSA(@Nonnull DSA dsa) {
        Optional<INode> possibleDigest = dsa.hasChildOfType(MessageDigest.class);
        if (possibleDigest.isEmpty()) {
            return dsa;
        }

        final INode digest = possibleDigest.get();
        if (digest instanceof SHA) {
            dsa.put(new Oid("1.2.840.10040.4.3", dsa.getDetectionContext()));
        } else if (digest instanceof SHA2 sha2) {
            sha2.getDigestSize()
                    .ifPresent(
                            digestSize -> {
                                switch (digestSize.getValue()) {
                                    case 224 ->
                                            dsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.1",
                                                            dsa.getDetectionContext()));
                                    case 256 ->
                                            dsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.2",
                                                            dsa.getDetectionContext()));
                                    case 384 ->
                                            dsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.3",
                                                            dsa.getDetectionContext()));
                                    case 512 ->
                                            dsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.4",
                                                            dsa.getDetectionContext()));
                                    default -> {
                                        // nothing
                                    }
                                }
                            });
        } else if (digest instanceof SHA3 sha3) {
            sha3.getDigestSize()
                    .ifPresent(
                            digestSize -> {
                                switch (digestSize.getValue()) {
                                    case 224 ->
                                            dsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.5",
                                                            dsa.getDetectionContext()));
                                    case 256 ->
                                            dsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.6",
                                                            dsa.getDetectionContext()));
                                    case 384 ->
                                            dsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.7",
                                                            dsa.getDetectionContext()));
                                    case 512 ->
                                            dsa.put(
                                                    new Oid(
                                                            "2.16.840.1.101.3.4.3.8",
                                                            dsa.getDetectionContext()));
                                    default -> {
                                        // nothing
                                    }
                                }
                            });
        }
        return dsa;
    }
}
