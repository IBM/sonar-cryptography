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
import com.ibm.mapper.model.IAsset;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.translator.JavaTranslator;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;

public final class SignerReorganizer {

    private SignerReorganizer() {
        // private
    }

    private static final IReorganizerRule RENAME_SIGNATURE =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Signature.class)
                    .forNodeValue(JavaTranslator.UNKNOWN)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                /*
                                 * The Signature node must have a MessageDigest child, and a child
                                 * which is one of the algorithm classes below and which has a name.
                                 * We can then name the Signature "DIGESTNAMEwithALGONAME"
                                 */
                                if (!node.hasChildOfType(MessageDigest.class).isPresent()) {
                                    return false;
                                }
                                List<Class<? extends Algorithm>> algorithmClasses =
                                        List.of(Algorithm.class, PublicKeyEncryption.class);
                                for (Class<? extends Algorithm> clazz : algorithmClasses) {
                                    if (node.hasChildOfType(clazz).isPresent()
                                            && !node.hasChildOfType(clazz)
                                                    .get()
                                                    .asString()
                                                    .equals(JavaTranslator.UNKNOWN)) {
                                        return true;
                                    }
                                }
                                return false;
                            })
                    .perform(
                            (node, parent, roots) -> {
                                INode algoChild = null;
                                INode messageDigestChild = null;
                                for (Map.Entry<Class<? extends INode>, INode> entry :
                                        node.getChildren().entrySet()) {
                                    Class<? extends INode> kind = entry.getKey();
                                    if (kind.equals(Algorithm.class)
                                            || kind.equals(PublicKeyEncryption.class)) {
                                        algoChild = entry.getValue();
                                    }
                                    if (kind.equals(MessageDigest.class)) {
                                        messageDigestChild = entry.getValue();
                                    }
                                }

                                String newSignatureName =
                                        messageDigestChild.asString().replace("-", "")
                                                + "with"
                                                + algoChild.asString();

                                // Create the new Signature node
                                DetectionLocation detectionLocation =
                                        ((IAsset) node).getDetectionContext();
                                Signature newSignature =
                                        new Signature(
                                                new Algorithm(newSignatureName, detectionLocation),
                                                detectionLocation);

                                // Add all the Signature children to the new Mac node
                                for (Map.Entry<Class<? extends INode>, INode> childKeyValue :
                                        node.getChildren().entrySet()) {
                                    newSignature.append(childKeyValue.getValue());
                                }

                                if (parent == null) {
                                    // `node` is a root node
                                    // Create a copy of the roots list
                                    List<INode> rootsCopy = new ArrayList<>(roots);
                                    for (int i = 0; i < rootsCopy.size(); i++) {
                                        if (rootsCopy.get(i).equals(node)) {
                                            rootsCopy.set(i, newSignature);
                                            break;
                                        }
                                    }
                                    return rootsCopy;
                                } else {
                                    // Replace the previous Signature node
                                    parent.append(newSignature);
                                    return roots;
                                }
                            });

    @Unmodifiable
    @Nonnull
    public static List<IReorganizerRule> rules() {
        return List.of(RENAME_SIGNATURE);
    }
}
