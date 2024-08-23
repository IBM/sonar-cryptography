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

import com.ibm.mapper.reorganizer.IReorganizerRule;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;

public final class SignerReorganizer {

    private SignerReorganizer() {
        // private
    }

    /*private static final IReorganizerRule RENAME_SIGNATURE_PSS =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Signature.class)
                    .forNodeValue(JavaTranslator.UNKNOWN + "-PSS")
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(BlockCipher.class)
                                            .withDetectionCondition(
                                                    (node, parent, roots) -> {
                                                        return !node.asString()
                                                                .contains(JavaTranslator.UNKNOWN);
                                                    })
                                            .noAction()))
                    .perform(
                            UsualPerformActions.performReplacingNode(
                                    (node, parent, roots) -> {
                                        INode blockCipherChild =
                                                node.hasChildOfType(BlockCipher.class).get();

                                        String newSignatureName =
                                                node.asString()
                                                        .replace(
                                                                JavaTranslator.UNKNOWN,
                                                                blockCipherChild.asString());

                                        // Create the new Signature node
                                        DetectionLocation detectionLocation =
                                                ((IAsset) node).getDetectionContext();
                                        return new Signature(
                                                new Algorithm(newSignatureName, detectionLocation));
                                    }));

    private static final IReorganizerRule RENAME_SIGNATURE_RSA =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Signature.class)
                    .forNodeValue(JavaTranslator.UNKNOWN + "withRSA")
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(MessageDigest.class)
                                            .withDetectionCondition(
                                                    (node, parent, roots) -> {
                                                        return !node.asString()
                                                                .contains(JavaTranslator.UNKNOWN);
                                                    })
                                            .noAction()))
                    .perform(
                            UsualPerformActions.performReplacingNode(
                                    (node, parent, roots) -> {
                                        INode messageDigestChild =
                                                node.hasChildOfType(MessageDigest.class).get();

                                        String newSignatureName =
                                                node.asString()
                                                        .replace(
                                                                JavaTranslator.UNKNOWN,
                                                                messageDigestChild
                                                                        .asString()
                                                                        .replace("-", ""));

                                        // Create the new Signature node
                                        DetectionLocation detectionLocation =
                                                ((IAsset) node).getDetectionContext();
                                        return new Signature(
                                                new Algorithm(newSignatureName, detectionLocation));
                                    }));

    private static final IReorganizerRule RENAME_SIGNATURE =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Signature.class)
                    .forNodeValue(JavaTranslator.UNKNOWN)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                 // The Signature node must have a MessageDigest child, and a child
                                 // which is one of the algorithm classes below and which has a name.
                                 // We can then name the Signature "DIGESTNAMEwithALGONAME"
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
                            UsualPerformActions.performReplacingNode(
                                    (node, parent, roots) -> {
                                        INode messageDigestChild =
                                                node.hasChildOfType(MessageDigest.class).get();

                                        INode algoChild = null;
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
                                        if (algoChild == null) {
                                            // This case should never happen (given the detection condition)
                                            return node;
                                        }

                                        String newSignatureName =
                                                messageDigestChild.asString().replace("-", "")
                                                        + "with"
                                                        + algoChild.asString();

                                        // Create the new Signature node
                                        DetectionLocation detectionLocation =
                                                ((IAsset) node).getDetectionContext();
                                        return new Signature(
                                                new Algorithm(newSignatureName, detectionLocation));
                                    }));

     */

    @Unmodifiable
    @Nonnull
    public static List<IReorganizerRule> rules() {
        return List.of(); // RENAME_SIGNATURE, RENAME_SIGNATURE_PSS, RENAME_SIGNATURE_RSA
    }
}
