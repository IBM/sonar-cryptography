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
package com.ibm.plugin.translation;

import com.ibm.enricher.Enricher;
import com.ibm.enricher.IEnricher;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.StreamCipher;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;

public class PythonEnricher implements IEnricher {

    public static final String TO_BE_ENRICHED =
            "-"; // Use it when translating nodes that will require there name to be derived during
    // Enrichment
    public static final List<Class<? extends INode>> entryPointsKinds =
            List.of(PrivateKey.class, PublicKey.class);
    public static final List<Class<? extends INode>> rootLevelKinds =
            List.of(PrivateKey.class, PublicKey.class);

    @Override
    public void enrich(@NotNull INode node) {
        enrichPrivateKeyWithAlgorithm(node);

        enrichPublicKeyAlgorithmWithPrivateKeyAlgorithmContent(node);

        enrichSignatureWithAlgorithm(node);
        enrichSignatureWithName(node); // Must happen after `enrichSignatureWithAlgorithm`
        enrichSignatureWithSignatureChild(node);

        enrichBlockCipherWithBlockSize(node);

        final Enricher enricher = new Enricher();
        enricher.enrich(node);
    }

    /**
     * This function should be applied at the very end of the enrichment/translation process. It
     * will extract the nodes of class listed in `rootLevelKinds` to make them root nodes. It is
     * important that this function gets applied after the other enrichments, as those may use links
     * between nodes that may be removed after calling this function.
     *
     * <p>TODO: For now, it only looks at children of the root private key node: should I make it
     * more general?
     *
     * @param values A list of nodes to enrich.
     * @return A new list of nodes with additional information.
     */
    public List<INode> enrichRootAfter(@Nonnull final List<INode> values) {
        List<INode> newValues = new ArrayList<>(values);
        Map<Class<? extends INode>, INode> nodesMap =
                values.stream().collect(Collectors.toMap(INode::getKind, n -> n));

        entryPointsKinds.forEach(
                entryPointKind ->
                        rootLevelKinds.forEach(
                                rootLevelKind -> {
                                    if (nodesMap.keySet().contains(entryPointKind)
                                            && !nodesMap.keySet().contains(rootLevelKind)) {
                                        INode privateKey = nodesMap.get(entryPointKind);
                                        INode publicKeyChild =
                                                privateKey.getChildren().get(rootLevelKind);
                                        if (publicKeyChild != null) {
                                            newValues.add(publicKeyChild.deepCopy());
                                            privateKey.removeChildOfType(rootLevelKind);
                                        }
                                    }
                                }));

        return newValues;
    }

    /**
     * This function should be applied at the very beginning of the enrichment process. It
     * processes/rearranges the root nodes before the application of the per-node enrichment. It is
     * important that this function gets applied before the other enrichments, as those may use
     * links between nodes that may result from calling this function.
     *
     * <p>This method takes a list of {@link INode} objects as input and returns a new list with
     * some additional information added to each node.
     *
     * @param values the list of {@link INode} objects to be enriched
     * @return a new list of {@link INode} objects with additional information added to each node
     */
    public List<INode> enrichRootBefore(@Nonnull final List<INode> values) {
        List<INode> newValues = new ArrayList<>(values);
        Map<Class<? extends INode>, INode> nodesMap =
                values.stream().collect(Collectors.toMap(INode::getKind, n -> n));

        // When the root contains a Cipher and a Mode (happens with the `CryptographyCipher` rule),
        // make the Mode a child of the Cipher
        if ((nodesMap.containsKey(BlockCipher.class) || nodesMap.containsKey(StreamCipher.class))
                && nodesMap.containsKey(Mode.class)) {
            INode cipher =
                    nodesMap.containsKey(BlockCipher.class)
                            ? nodesMap.get(BlockCipher.class)
                            : nodesMap.get(StreamCipher.class);
            INode mode = nodesMap.get(Mode.class);
            cipher.append(mode);
            newValues.remove(mode);
        }

        // When the root contains a PasswordBasedKeyDerivationFunction, make it the parent of some
        // other detected root nodes
        if (nodesMap.containsKey(KeyDerivationFunction.class)
                || nodesMap.containsKey(PasswordBasedKeyDerivationFunction.class)) {
            INode kdf =
                    nodesMap.containsKey(KeyDerivationFunction.class)
                            ? nodesMap.get(KeyDerivationFunction.class)
                            : nodesMap.get(PasswordBasedKeyDerivationFunction.class);
            for (Object clazz :
                    List.of(
                            MessageDigest.class,
                            BlockCipher.class,
                            KeyLength.class,
                            NumberOfIterations.class)) {
                if (nodesMap.containsKey(clazz)) {
                    INode node = nodesMap.get(clazz);
                    kdf.append(node);
                    newValues.remove(node);
                }
            }
        }

        return newValues;
    }

    private void enrichSignatureWithAlgorithm(INode node) {
        // If a PrivateKey has a Signature child, enrich the Signature with the algorithm
        // information from the private key
        if (!(node instanceof PrivateKey privateKey)) {
            return;
        }
        INode signatureChild = privateKey.getChildren().get(Signature.class);
        if (signatureChild == null) {
            return;
        }

        if (privateKey.getChildren().get(EllipticCurveAlgorithm.class)
                instanceof
                EllipticCurveAlgorithm algorithmChild) { // `instanceof` also performs null check

            // Create a new EllipticCurveAlgorithm node
            EllipticCurveAlgorithm algorithmChildOfSignature =
                    new EllipticCurveAlgorithm(
                            new Algorithm(
                                    algorithmChild.getName(), privateKey.getDetectionContext()));
            INode elliptiCurveChild = algorithmChild.getChildren().get(EllipticCurve.class);
            if (elliptiCurveChild != null) {
                // Add the EllipticCurve if it exists
                algorithmChildOfSignature.append(elliptiCurveChild.deepCopy());
            }

            // Add the Algorithm to the Signature only when the Signature does not yet have
            // EllipticCurveAlgorithm information
            if (signatureChild.getChildren().get(EllipticCurveAlgorithm.class) == null) {
                signatureChild.append(algorithmChildOfSignature);
            }
        } else if (privateKey.getChildren().get(Algorithm.class)
                instanceof Algorithm algorithmChild) { // `instanceof` also performs null check

            // Create a new Algorithm node
            Algorithm algorithmChildOfSignature =
                    new Algorithm(algorithmChild.getName(), privateKey.getDetectionContext());
            INode keyLengthChild = privateKey.getChildren().get(KeyLength.class);
            if (keyLengthChild != null) {
                // Add the KeyLength if it exists
                algorithmChildOfSignature.append(keyLengthChild.deepCopy());
            }

            // Add the Algorithm to the Signature only when the Signature does not yet have
            // Algorithm information
            if (signatureChild.getChildren().get(Algorithm.class) == null) {
                signatureChild.append(algorithmChildOfSignature);
            }
        }
    }

    private void enrichSignatureWithName(INode node) {
        // If a PrivateKey has a Signature child with no name (TO_BE_ENRICHED), replace it with a
        // name derived from its children
        if (node instanceof PrivateKey privateKey) {
            Signature signature = (Signature) privateKey.getChildren().get(Signature.class);
            if (signature == null || !signature.getName().equals(TO_BE_ENRICHED)) {
                return;
            }

            MessageDigest digestChild =
                    (MessageDigest) signature.getChildren().get(MessageDigest.class);
            Algorithm algorithmChild = (Algorithm) signature.getChildren().get(Algorithm.class);
            if (digestChild == null || algorithmChild == null) {
                return;
            }

            // Default signature name when the Signature contains a MessageDigest and an Algorithm
            String signatureName = digestChild.getName() + "with" + algorithmChild.getName();

            // When the signature additionally contains a ProbabilisticSignatureScheme with the RSA
            // algorithm, its name is different
            ProbabilisticSignatureScheme pssChild =
                    (ProbabilisticSignatureScheme)
                            signature.getChildren().get(ProbabilisticSignatureScheme.class);
            if (pssChild != null && algorithmChild.getName().equals("RSA")) {
                signatureName = "RSASSA-PSS";
            }

            // Create the new Signature node with the updated name, and add all of its children
            Signature signatureWithName =
                    new Signature(new Algorithm(signatureName, signature.getDetectionContext()));
            signature.getChildren().forEach((k, v) -> signatureWithName.append(v));
            privateKey.append(signatureWithName);
        }
    }

    private void enrichSignatureWithSignatureChild(INode node) {
        // If a PrivateKey has a Signature child 1 that itself has a Signature child 2, and that
        // Signature 2 has a Name but not Signature 1,
        // then make Signature 2 the new child of PrivateKey, to which we append all nodes of
        // Signature 1 (except the Signature node)
        if (node instanceof PrivateKey privateKey
                && privateKey.getChildren().get(Signature.class)
                        instanceof Signature signatureChild) {
            if (!signatureChild.getName().equals(TO_BE_ENRICHED)) {
                return;
            }

            Signature signatureGrandChild =
                    (Signature) signatureChild.getChildren().get(Signature.class);
            if (signatureGrandChild == null
                    || signatureGrandChild.getName().equals(TO_BE_ENRICHED)) {
                return;
            }

            INode newSignatureNode = signatureGrandChild.deepCopy();

            signatureChild
                    .getChildren()
                    .forEach(
                            (k, v) -> {
                                if (!(v instanceof Signature)) {
                                    newSignatureNode.append(v);
                                }
                            });

            privateKey.append(newSignatureNode);
        }
    }

    private void enrichPrivateKeyWithAlgorithm(INode node) {
        // If a PublicKey has a PrivateKey child, enrich the PrivateKey with the algorithm
        // information from the PublicKey
        if (node instanceof PublicKey publicKey
                && publicKey.getChildren().get(EllipticCurveAlgorithm.class)
                        instanceof // `instanceof` also performs null check
                        EllipticCurveAlgorithm algorithmChild) {
            INode privateKeyChild = publicKey.getChildren().get(PrivateKey.class);
            if (privateKeyChild == null) {
                return;
            }

            // Add the Algorithm to the PrivateKey only when the PrivateKey does not yet have
            // EllipticCurveAlgorithm information
            if (privateKeyChild.getChildren().get(EllipticCurveAlgorithm.class) == null) {
                privateKeyChild.append(algorithmChild.deepCopy());
            }
        }
    }

    private void enrichPublicKeyAlgorithmWithPrivateKeyAlgorithmContent(INode node) {
        // If a PrivateKey has an Algorithm child, and a PublicKey child that itself has an
        // Algorithm child, enrich PublicKey's Algorithm with PrivateKey's Algorithm children nodes
        if (node instanceof PrivateKey privateKey
                && privateKey.getChildren().get(Algorithm.class)
                        instanceof Algorithm algorithmPrivateKey
                && privateKey.getChildren().get(PublicKey.class) instanceof PublicKey publicKey
                && publicKey.getChildren().get(Algorithm.class)
                        instanceof
                        Algorithm algorithmPublicKey) { // `instanceof` also performs null check
            algorithmPrivateKey
                    .getChildren()
                    .forEach(
                            (k, v) -> {
                                if (algorithmPublicKey.hasChildOfType(k).isEmpty()) {
                                    algorithmPublicKey.append(v.deepCopy());
                                }
                            });
        }
    }

    private void enrichBlockCipherWithBlockSize(INode node) {
        // If a BlockCipher has a Padding child that itself has a BlockSize child, move the
        // BlockSize node underneath the BlockCipher node
        if (node instanceof BlockCipher blockCipher
                && blockCipher.getChildren().get(Padding.class) instanceof Padding padding
                && padding.getChildren().get(BlockSize.class) instanceof BlockSize blockSize) {
            blockCipher.append(blockSize);
            padding.removeChildOfType(BlockSize.class);
        }
    }
}
