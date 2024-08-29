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

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.Optional;

public final class PaddingReorganizer {

    private PaddingReorganizer() {
        // nothing
    }

    public static final IReorganizerRule MOVE_OAEP_UNDER_ALGORITHM =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                final Optional<INode> functionality =
                                        node.hasChildOfType(Decrypt.class);
                                final Optional<INode> pke =
                                        node.hasChildOfType(PublicKeyEncryption.class);
                                if (functionality.isEmpty()) {
                                    return false;
                                }
                                if (pke.isEmpty()) {
                                    return false;
                                }

                                return functionality
                                        .get()
                                        .hasChildOfType(Padding.class)
                                        .map(OAEP.class::isInstance)
                                        .orElse(false);
                            })
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<INode> pke =
                                        node.hasChildOfType(PublicKeyEncryption.class);
                                final Optional<INode> functionality =
                                        node.hasChildOfType(Decrypt.class);
                                if (functionality.isEmpty()) {
                                    return roots;
                                }
                                if (pke.isEmpty()) {
                                    return roots;
                                }

                                functionality
                                        .get()
                                        .hasChildOfType(Padding.class)
                                        .ifPresent(
                                                p -> {
                                                    pke.get().put(p);
                                                    functionality
                                                            .get()
                                                            .removeChildOfType(p.getKind());
                                                });
                                return roots;
                            });
}
