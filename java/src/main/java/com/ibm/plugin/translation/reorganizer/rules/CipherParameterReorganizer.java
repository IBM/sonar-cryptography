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
package com.ibm.plugin.translation.reorganizer.rules;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import com.ibm.mapper.utils.Function3;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;

public final class CipherParameterReorganizer {

    private CipherParameterReorganizer() {
        // private
    }

    /* Used for AEADParameters */
    @Nonnull
    private static final IReorganizerRule MOVE_KEY_LENGTH_UP =
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
                                INode keyLengthChild =
                                        node.getChildren().get(KeyLength.class).deepCopy();
                                if (parent == null) {
                                    // Do nothing
                                    return roots;
                                } else {
                                    // Append the KeyLength to the parent and remove it from the
                                    // TagLength node
                                    parent.append(keyLengthChild);
                                    node.removeChildOfType(KeyLength.class);
                                    return roots;
                                }
                            });

    @Nonnull
    private static final Function3<INode, INode, List<INode>, List<INode>> performMovingChildrenUp =
            (node, parent, roots) -> {
                if (parent == null) {
                    // Do nothing
                    return roots;
                }
                for (Map.Entry<Class<? extends INode>, INode> entry :
                        node.getChildren().entrySet()) {
                    Class<? extends INode> kind = entry.getKey();
                    INode child = entry.getValue();
                    // Append the child to `parent` and remove it from `node`
                    parent.append(child);
                    node.removeChildOfType(kind);
                }
                return roots;
            };

    @Nonnull
    private static final IReorganizerRule MOVE_NODES_UNDER_ENCRYPT_UP =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Encrypt.class)
                    .withAnyNonNullChildren()
                    .perform(performMovingChildrenUp);

    @Nonnull
    private static final IReorganizerRule MOVE_NODES_UNDER_DECRYPT_UP =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Decrypt.class)
                    .withAnyNonNullChildren()
                    .perform(performMovingChildrenUp);

    @Unmodifiable
    @Nonnull
    public static List<IReorganizerRule> rules() {
        return List.of(
                MOVE_KEY_LENGTH_UP, MOVE_NODES_UNDER_ENCRYPT_UP, MOVE_NODES_UNDER_DECRYPT_UP);
    }
}
