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
package com.ibm.enricher;

import com.ibm.enricher.algorithm.AESEnricher;
import com.ibm.enricher.algorithm.DESEnricher;
import com.ibm.enricher.algorithm.DHEnricher;
import com.ibm.enricher.algorithm.DSAEnricher;
import com.ibm.enricher.algorithm.PBKDF2Enricher;
import com.ibm.enricher.algorithm.RSAEnricher;
import com.ibm.enricher.algorithm.SHA2Enricher;
import com.ibm.enricher.algorithm.SHA3Enricher;
import com.ibm.enricher.algorithm.SignatureEnricher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DES;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;
import java.util.Collection;

/**
 * This enricher instance operates on a language-agnostic level, meaning it will enrich the given
 * list of nodes with general cryptographic knowledge, such as OIDs. This does not include
 * language-specific information like default key sizes. Therefore, create a library-specific
 * enricher instance as part of the language package.
 */
public class Enricher implements IEnricher {
    /**
     * Enriches a list of nodes with additional information.
     *
     * @param nodes The list of nodes to enrich
     */
    @Nonnull
    public static Collection<INode> enrich(@Nonnull final Collection<INode> nodes) {
        final Enricher enricher = new Enricher();
        return nodes.stream()
                .map(
                        node -> {
                            final INode enriched = enricher.enrich(node);
                            enrich(enriched.getChildren().values()).forEach(enriched::append);
                            return enriched;
                        })
                .toList();
    }

    /**
     * Enriches the given node with additional information.
     *
     * @param node The node to enrich
     */
    @NotNull @Override
    public INode enrich(@Nonnull INode node) {
        if (node instanceof AES aes) {
            node = new AESEnricher().enrich(aes);
        }
        if (node instanceof DES des) {
            node = new DESEnricher().enrich(des);
        }

        if (node instanceof RSA rsa) {
            node = new RSAEnricher().enrich(rsa);
        }
        if (node instanceof DH dh) {
            node = new DHEnricher().enrich(dh);
        }
        if (node instanceof DSA dsa) {
            node = new DSAEnricher().enrich(dsa);
        }

        if (node instanceof SHA2 sha2) {
            node = new SHA2Enricher().enrich(sha2);
        }
        if (node instanceof SHA3 sha3) {
            node = new SHA3Enricher().enrich(sha3);
        }

        if (node instanceof PBKDF2 pbkdf2) {
            node = new PBKDF2Enricher().enrich(pbkdf2);
        }

        if (node instanceof Signature signature) {
            node = new SignatureEnricher().enrich(signature);
        }
        return node;
    }
}
