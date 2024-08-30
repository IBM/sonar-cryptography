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
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.Optional;
import javax.annotation.Nonnull;

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

    public static final IReorganizerRule MOVE_DIGEST_FROM_SIGN_ACTION_UNDER_SIGNATURE =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(Sign.class)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                if (parent != null) {
                                    return parent instanceof Key
                                            && node.hasChildOfType(MessageDigest.class).isPresent()
                                            && parent.hasChildOfType(Signature.class).isPresent();
                                }
                                return false;
                            })
                    .perform(
                            (node, parent, roots) -> {
                                if (parent == null) {
                                    return roots;
                                }

                                final Optional<INode> possibleDigest =
                                        node.hasChildOfType(MessageDigest.class);
                                final Optional<INode> possibleSignature =
                                        parent.hasChildOfType(Signature.class);

                                if (possibleSignature.isEmpty()) {
                                    return roots;
                                }
                                if (possibleDigest.isEmpty()) {
                                    return roots;
                                }

                                possibleSignature.get().put(possibleDigest.get());
                                node.removeChildOfType(MessageDigest.class);
                                return roots;
                            });

    public static final IReorganizerRule MERGE_SIGNATURE_WITH_PKE_UNDER_PRIVATE_KEY =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    node.hasChildOfType(PublicKeyEncryption.class).isPresent()
                                            && node.hasChildOfType(Signature.class).isPresent())
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<INode> pke =
                                        node.hasChildOfType(PublicKeyEncryption.class);
                                final Optional<INode> s = node.hasChildOfType(Signature.class);
                                if (pke.isPresent() && s.isPresent()) {
                                    pke.get()
                                            .hasChildOfType(EllipticCurve.class)
                                            .ifPresent(e -> s.get().put(e));
                                    node.removeChildOfType(pke.get().getKind());
                                }
                                return roots;
                            });

    @Nonnull
    public static final IReorganizerRule MOVE_PSS_FROM_UNDER_SIGN_FUNCTION_TO_UNDER_KEY =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) -> {
                                final Optional<INode> func = node.hasChildOfType(Sign.class);
                                return func.filter(
                                                iNode ->
                                                        node.hasChildOfType(
                                                                                PublicKeyEncryption
                                                                                        .class)
                                                                        .isPresent()
                                                                && iNode.hasChildOfType(
                                                                                ProbabilisticSignatureScheme
                                                                                        .class)
                                                                        .isPresent())
                                        .isPresent();
                            })
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<INode> func = node.hasChildOfType(Sign.class);
                                if (func.isPresent()) {
                                    func.get()
                                            .hasChildOfType(ProbabilisticSignatureScheme.class)
                                            .ifPresent(
                                                    pss -> {
                                                        node.put(pss);
                                                        func.get()
                                                                .removeChildOfType(
                                                                        ProbabilisticSignatureScheme
                                                                                .class);
                                                    });
                                    // move as child of PSS
                                    func.get()
                                            .hasChildOfType(MessageDigest.class)
                                            .ifPresent(
                                                    digest -> {
                                                        node.hasChildOfType(
                                                                        ProbabilisticSignatureScheme
                                                                                .class)
                                                                .ifPresent(
                                                                        pss -> {
                                                                            pss.put(digest);
                                                                        });
                                                        func.get()
                                                                .removeChildOfType(
                                                                        MessageDigest.class);
                                                    });
                                    node.hasChildOfType(PublicKeyEncryption.class)
                                            .ifPresent(n -> node.removeChildOfType(n.getKind()));
                                }
                                return roots;
                            });
}
