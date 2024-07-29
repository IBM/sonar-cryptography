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

import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import com.ibm.plugin.translation.translator.JavaTranslator;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;

public final class AsymmetricBlockCipherReorganizer {

    private AsymmetricBlockCipherReorganizer() {
        // private
    }

    @Nonnull
    private static final IReorganizerRule MERGE_PKE =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(PublicKeyEncryption.class)
                    .forNodeValue(JavaTranslator.UNKNOWN)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(PublicKeyEncryption.class)
                                            .noAction()))
                    .perform(
                            (node, parent, roots) -> {
                                INode newPke =
                                        node.getChildren()
                                                .get(PublicKeyEncryption.class)
                                                .deepCopy();

                                for (Map.Entry<Class<? extends INode>, INode> childKeyValue :
                                        node.getChildren().entrySet()) {
                                    if (!childKeyValue.getKey().equals(PublicKeyEncryption.class)) {
                                        newPke.append(childKeyValue.getValue());
                                    }
                                }

                                if (parent == null) {
                                    // `node` is a root node
                                    // Create a copy of the roots list
                                    List<INode> rootsCopy = new ArrayList<>(roots);
                                    for (int i = 0; i < rootsCopy.size(); i++) {
                                        if (rootsCopy.get(i).equals(node)) {
                                            rootsCopy.set(i, newPke);
                                            break;
                                        }
                                    }
                                    return rootsCopy;
                                } else {
                                    // Replace the previous PublicKeyEncryption node
                                    parent.append(newPke);
                                    return roots;
                                }
                            });

    @Nonnull
    private static final IReorganizerRule INVERT_DIGEST_AND_ITS_SIZE =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(DigestSize.class)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(MessageDigest.class)
                                            .noAction()))
                    .perform(
                            (node, parent, roots) -> {
                                if (parent == null) {
                                    // Do nothing
                                    return roots;
                                }

                                INode messageDigestChild =
                                        node.getChildren().get(MessageDigest.class).deepCopy();

                                /* Append the DigestSize (without its DigestSize) child to the new DigestSize */
                                INode digestSize = node.deepCopy();
                                digestSize.removeChildOfType(MessageDigest.class);
                                messageDigestChild.append(digestSize);

                                // Append the MessageDigest to the parent
                                parent.append(messageDigestChild);
                                return roots;
                            });

    @Nonnull
    private static final IReorganizerRule MOVE_HASH_UNDER_OAEP =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(BlockCipher.class)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(OAEP.class)
                                            .noAction(),
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(MessageDigest.class)
                                            .noAction()))
                    .perform(
                            (node, parent, roots) -> {
                                INode oaepChild = node.getChildren().get(OAEP.class);
                                INode messageDigestChild =
                                        node.getChildren().get(MessageDigest.class).deepCopy();

                                // Add the message digest under the OAEP node
                                oaepChild.append(messageDigestChild);
                                // Remove the message digest from the BlockCipher's children
                                node.removeChildOfType(MessageDigest.class);

                                return roots;
                            });

    @Unmodifiable
    @Nonnull
    public static List<IReorganizerRule> rules() {
        return List.of(MERGE_PKE, INVERT_DIGEST_AND_ITS_SIZE, MOVE_HASH_UNDER_OAEP);
    }
}
