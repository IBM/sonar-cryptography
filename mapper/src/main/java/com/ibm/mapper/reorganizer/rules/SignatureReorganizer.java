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

import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Functionality;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.UsualPerformActions;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;

public final class SignatureReorganizer {

    private SignatureReorganizer() {
        // private
    }

    @Nonnull
    public static final IReorganizerRule MERGE_UNKNOWN_SIGNATURE_PARENT_AND_CHILD =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("MERGE_SIGNATURE_UNKNOWN_PARENT_AND_CHILD")
                    .forNodeKind(Signature.class)
                    .forNodeValue(ITranslator.UNKNOWN)
                    .includingChildren(
                            List.of(
                                    new ReorganizerRuleBuilder()
                                            .createReorganizerRule()
                                            .forNodeKind(Signature.class)
                                            .noAction()))
                    .perform(
                            UsualPerformActions.performMergeParentAndChildOfSameKind(
                                    Signature.class));

    @Nonnull
    public static final IReorganizerRule MERGE_SIGNATURE_WITH_PKE_UNDER_PRIVATE_KEY =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("MERGE_SIGNATURE_WITH_PKE_UNDER_PRIVATE_KEY")
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
                    .createReorganizerRule("MOVE_PSS_FROM_UNDER_SIGN_FUNCTION_TO_UNDER_KEY")
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
                                                                .ifPresent(pss -> pss.put(digest));
                                                        func.get()
                                                                .removeChildOfType(
                                                                        MessageDigest.class);
                                                    });
                                    node.hasChildOfType(PublicKeyEncryption.class)
                                            .ifPresent(n -> node.removeChildOfType(n.getKind()));
                                }
                                return roots;
                            });

    @Nonnull
    public static final IReorganizerRule MAKE_RSA_TO_SIGNATURE =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule("MAKE_RSA_TO_SIGNATURE")
                    .forNodeKind(PrivateKey.class)
                    .withDetectionCondition(
                            (node, parent, roots) ->
                                    node.hasChildOfType(PublicKeyEncryption.class)
                                            .filter(
                                                    iNode ->
                                                            node.hasChildOfType(Sign.class)
                                                                            .isPresent()
                                                                    && iNode instanceof RSA)
                                            .isPresent())
                    .perform(
                            (node, parent, roots) -> {
                                final Optional<INode> pke =
                                        node.hasChildOfType(PublicKeyEncryption.class);
                                if (pke.isPresent() && pke.get() instanceof RSA rsa) {
                                    node.put(new RSA(Signature.class, rsa));
                                    node.removeChildOfType(pke.get().getKind());
                                }
                                return roots;
                            });

    @Nonnull
    public static IReorganizerRule moveNodesFromUnderFunctionalityUnderNode(
            @Nonnull Class<? extends Functionality> functionalityClazz,
            @Nonnull Class<? extends INode> underNodeClazz) {
        return new ReorganizerRuleBuilder()
                .createReorganizerRule()
                .forNodeKind(functionalityClazz)
                .withDetectionCondition(
                        (node, parent, roots) -> {
                            if (parent != null) {
                                return parent.hasChildOfType(underNodeClazz).isPresent();
                            }
                            return false;
                        })
                .perform(
                        (node, parent, roots) -> {
                            Optional.ofNullable(parent)
                                    .flatMap(p -> p.hasChildOfType(underNodeClazz))
                                    .ifPresent(
                                            n -> {
                                                for (Map.Entry<Class<? extends INode>, INode>
                                                        childKeyValue :
                                                                node.getChildren().entrySet()) {
                                                    n.put(childKeyValue.getValue());
                                                    node.removeChildOfType(childKeyValue.getKey());
                                                }
                                            });
                            return null;
                        });
    }
}
