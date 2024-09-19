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
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.UsualPerformActions;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

public final class CipherParameterReorganizer {

    private CipherParameterReorganizer() {
        // private
    }

    /* Used for AEADParameters */
    @Nonnull
    public static final IReorganizerRule MOVE_KEY_LENGTH_UNDER_TAG_LENGTH_UP =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(TagLength.class)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(KeyLength.class)
                                            .noAction()))
                    .perform(
                            (node, parent, roots) -> {
                                INode keyLengthChild = node.getChildren().get(KeyLength.class);
                                if (parent == null) {
                                    // Do nothing
                                    return roots;
                                } else {
                                    // Append the KeyLength to the parent and remove it from the
                                    // TagLength node
                                    parent.put(keyLengthChild);
                                    node.removeChildOfType(KeyLength.class);
                                    return roots;
                                }
                            });

    @Nonnull
    public static final IReorganizerRule MOVE_NODES_UNDER_ENCRYPT_UP =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Encrypt.class)
                    .withAnyNonNullChildren()
                    .perform(UsualPerformActions.performMovingChildrenUp);

    @Nonnull
    public static final IReorganizerRule MOVE_NODES_UNDER_DECRYPT_UP =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Decrypt.class)
                    .withAnyNonNullChildren()
                    .perform(UsualPerformActions.performMovingChildrenUp);
}
