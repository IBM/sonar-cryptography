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
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class MacReorganizer {
    private static final Logger LOGGER = LoggerFactory.getLogger(MacReorganizer.class);

    private MacReorganizer() {
        // private
    }

    @Nonnull
    private static final IReorganizerRule MOVE_NODES_UNDER_CIPHER =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Mac.class)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                return (node.hasChildOfType(BlockCipher.class).isPresent()
                                                || node.hasChildOfType(StreamCipher.class)
                                                        .isPresent())
                                        && (node.hasChildOfType(Mode.class).isPresent()
                                                || node.hasChildOfType(Padding.class).isPresent()
                                                || node.hasChildOfType(BlockSize.class)
                                                        .isPresent());
                            })
                    .perform(
                            (node, parent, roots) -> {
                                INode cipherParent = null;
                                for (Map.Entry<Class<? extends INode>, INode> entry :
                                        node.getChildren().entrySet()) {
                                    Class<? extends INode> kind = entry.getKey();
                                    if (kind.equals(BlockCipher.class)
                                            || kind.equals(StreamCipher.class)) {
                                        if (cipherParent != null) {
                                            // Detect when there are mutliple cipher parents
                                            LOGGER.warn(
                                                    "A Mac node has both BlockCipher and StreamCipher children");
                                        }
                                        cipherParent = entry.getValue();
                                    }
                                }
                                if (cipherParent == null) {
                                    // Do nothing
                                    return roots;
                                }

                                for (Iterator<Map.Entry<Class<? extends INode>, INode>> iterator =
                                                node.getChildren().entrySet().iterator();
                                        iterator.hasNext(); ) {
                                    Map.Entry<Class<? extends INode>, INode> entry =
                                            iterator.next();
                                    Class<? extends INode> kind = entry.getKey();
                                    if (kind.equals(Mode.class)
                                            || kind.equals(Padding.class)
                                            || kind.equals(BlockSize.class)) {
                                        INode child = entry.getValue();
                                        // Append the child to `cipherParent`
                                        // (only when `cipherParent` does not already have such a
                                        // child)
                                        if (cipherParent.hasChildOfType(kind).isEmpty()) {
                                            cipherParent.append(child);
                                        }
                                        // Remove the entry from iterator (to avoid concurrency
                                        // issues)
                                        iterator.remove();
                                        // Remove the child from the current `node`
                                        node.removeChildOfType(kind);
                                    }
                                }
                                return roots;
                            });

    /*
    private static final IReorganizerRule RENAME_MAC =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(HMAC.class)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                return node.asString().contains(ITranslator.UNKNOWN)
                                        && (node.hasChildOfType(BlockCipher.class).isPresent()
                                                || node.hasChildOfType(StreamCipher.class)
                                                        .isPresent()
                                                || node.hasChildOfType(MessageDigest.class)
                                                        .isPresent());
                            })
                    .perform(
                            (node, parent, roots) -> {
                                // Get the child node which defines the name of the Mac
                                // Typically, a BlockCipher, StreamCipher or MessageDigest
                                INode referenceChild = null;
                                for (Map.Entry<Class<? extends INode>, INode> entry :
                                        node.getChildren().entrySet()) {
                                    Class<? extends INode> kind = entry.getKey();
                                    if (kind.equals(BlockCipher.class)
                                            || kind.equals(StreamCipher.class)
                                            || kind.equals(MessageDigest.class)) {
                                        if (referenceChild != null) {
                                            // Detect when there are mutliple "reference" children
                                            LOGGER.warn(
                                                    "Mac name must be determined by a BlockCipher, StreamCipher or MessageDigest child, but the mac has several of these children. It will use the "
                                                            + kind.getSimpleName());
                                        }
                                        referenceChild = entry.getValue();
                                    }
                                }

                                // Create the new name of the Mac node by replacing the UNKNOWN part.
                                // TODO: This is a simple version where we use only the name of the reference child,
                                // but it could be modified to include infromation from a potential mode or size subchild
                                String newMacName =
                                        node.asString()
                                                .replace(
                                                        ITranslator.UNKNOWN,
                                                        referenceChild.asString());

                                // Create the new Mac node
                                DetectionLocation detectionLocation =
                                        ((IAsset) node).getDetectionContext();
                                HMAC newMac =
                                        new HMAC(new Algorithm(newMacName, detectionLocation));

                                // Add all the Mac children to the new Mac node
                                for (Map.Entry<Class<? extends INode>, INode> childKeyValue :
                                        node.getChildren().entrySet()) {
                                    newMac.append(childKeyValue.getValue());
                                }

                                if (parent == null) {
                                    // `node` is a root node
                                    // Create a copy of the roots list
                                    List<INode> rootsCopy = new ArrayList<>(roots);
                                    for (int i = 0; i < rootsCopy.size(); i++) {
                                        if (rootsCopy.get(i).equals(node)) {
                                            rootsCopy.set(i, newMac);
                                            break;
                                        }
                                    }
                                    return rootsCopy;
                                } else {
                                    // Replace the previous Mac node
                                    parent.append(newMac);
                                    return roots;
                                }
                            });*/

    @Unmodifiable
    @Nonnull
    public static List<IReorganizerRule> rules() {
        return List.of(MOVE_NODES_UNDER_CIPHER); // RENAME_MAC
    }
}
