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
package com.ibm.mapper.reorganizer.rules;

import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.Optional;

public final class KeyAgreementReorganizer {

    private KeyAgreementReorganizer() {
        // nothing
    }

    public static final IReorganizerRule MERGE_KEYAGREEMENT_WITH_PKE_UNDER_PRIVATE_KEY =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    node.hasChildOfType(PublicKeyEncryption.class).isPresent()
                                            && node.hasChildOfType(KeyAgreement.class).isPresent())
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<INode> pke =
                                        node.hasChildOfType(PublicKeyEncryption.class);
                                final Optional<INode> ka = node.hasChildOfType(KeyAgreement.class);
                                if (pke.isPresent() && ka.isPresent()) {
                                    pke.get()
                                            .hasChildOfType(EllipticCurve.class)
                                            .ifPresent(e -> ka.get().put(e));
                                    node.removeChildOfType(pke.get().getKind());
                                }
                                return roots;
                            });
}
