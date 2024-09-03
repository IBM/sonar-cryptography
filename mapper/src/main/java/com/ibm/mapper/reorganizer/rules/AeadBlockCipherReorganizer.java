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

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;

public final class AeadBlockCipherReorganizer {

    private AeadBlockCipherReorganizer() {
        // private
    }

    @Nonnull
    private static final IReorganizerRule MERGE_AE_PARENT_AND_CHILD =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(AuthenticatedEncryption.class)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(AuthenticatedEncryption.class)
                                            .noAction()))
                    .perform(
                            (node, parent, roots) -> {
                                Algorithm newAuthenticatedEncryption =
                                        (Algorithm)
                                                node.getChildren()
                                                        .get(AuthenticatedEncryption.class);

                                for (Map.Entry<Class<? extends INode>, INode> childKeyValue :
                                        node.getChildren().entrySet()) {
                                    if (!childKeyValue
                                            .getKey()
                                            .equals(AuthenticatedEncryption.class)) {
                                        newAuthenticatedEncryption.put(childKeyValue.getValue());
                                    }
                                }

                                if (parent == null) {
                                    // `node` is a root node
                                    // Create a copy of the roots list
                                    List<INode> rootsCopy = new ArrayList<>(roots);
                                    for (int i = 0; i < rootsCopy.size(); i++) {
                                        if (rootsCopy.get(i).equals(node)) {
                                            rootsCopy.set(i, newAuthenticatedEncryption);
                                            break;
                                        }
                                    }
                                    return rootsCopy;
                                } else {
                                    // Replace the previous AuthenticatedEncryption node
                                    parent.put(newAuthenticatedEncryption);
                                    return roots;
                                }
                            });

    @Nonnull
    private static final IReorganizerRule MOVE_TAG_LENGTH_UNDER_MAC =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(AuthenticatedEncryption.class)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(Mac.class)
                                            .noAction(),
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(TagLength.class)
                                            .noAction()))
                    .perform(
                            (node, parent, roots) -> {
                                TagLength tagLength =
                                        (TagLength) node.getChildren().get(TagLength.class);
                                Mac mac = (Mac) node.getChildren().get(Mac.class);

                                mac.put(tagLength);
                                node.removeChildOfType(TagLength.class);
                                return roots;
                            });

    @Unmodifiable
    @Nonnull
    public static List<IReorganizerRule> rules() {
        return List.of(MERGE_AE_PARENT_AND_CHILD, MOVE_TAG_LENGTH_UNDER_MAC);
    }
}
