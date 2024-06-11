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

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import com.ibm.plugin.translation.translator.JavaTranslator;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;

public final class BlockCipherReorganizer {

    private BlockCipherReorganizer() {
        // private
    }

    private static final IReorganizerRule MERGE_BLOCK_CIPHER =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(BlockCipher.class)
                    .forNodeValue(JavaTranslator.UNKNOWN)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(BlockCipher.class)
                                            .noAction()))
                    .perform(
                            (node, parent, roots) -> {
                                Algorithm newBlockCipher =
                                        (Algorithm)
                                                node.getChildren()
                                                        .get(BlockCipher.class)
                                                        .deepCopy();

                                for (Map.Entry<Class<? extends INode>, INode> childKeyValue :
                                        node.getChildren().entrySet()) {
                                    if (!childKeyValue.getKey().equals(BlockCipher.class)) {
                                        newBlockCipher.append(childKeyValue.getValue());
                                    }
                                }

                                if (parent == null) {
                                    // `node` is a root node
                                    // Create a copy of the roots list
                                    List<INode> rootsCopy = new ArrayList<>(roots);
                                    for (int i = 0; i < rootsCopy.size(); i++) {
                                        if (rootsCopy.get(i).equals(node)) {
                                            rootsCopy.set(i, newBlockCipher);
                                            break;
                                        }
                                    }
                                    return rootsCopy;
                                } else {
                                    // Replace the previous BlockCipher node
                                    parent.append(newBlockCipher);
                                    return roots;
                                }
                            });

    @Unmodifiable
    @Nonnull
    public static List<IReorganizerRule> rules() {
        return List.of(MERGE_BLOCK_CIPHER);
    }
}
