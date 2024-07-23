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
package com.ibm.plugin.translation.translator;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.context.PRNGContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.ProtocolContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.translator.contexts.JavaAlgorithmParameterContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaCipherContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaDigestContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaKeyAgreementContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaMacContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaPRNGContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaProtocolContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaSecretKeyContextTranslator;
import com.ibm.plugin.translation.translator.contexts.JavaSignatureContextTranslator;
import org.jetbrains.annotations.Unmodifiable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.location.Position;
import org.sonar.plugins.java.api.location.Range;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.EnumConstantTree;
import org.sonar.plugins.java.api.tree.MethodInvocationTree;
import org.sonar.plugins.java.api.tree.NewClassTree;
import org.sonar.plugins.java.api.tree.SyntaxToken;
import org.sonar.plugins.java.api.tree.Tree;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public final class JavaTranslator
        extends ITranslator<JavaCheck, Tree, Symbol, JavaFileScannerContext> {

    private static final Logger LOGGER = LoggerFactory.getLogger(JavaTranslator.class);
    @Nonnull private final JavaMapperConfig javaMapperConfig = new JavaMapperConfig();

    public JavaTranslator() {
        // nothing
    }

    /**
     * The translation method is responsible for translating the provided detection store. It
     * performs several important tasks within its implementation: <br>
     * retrieve the detection values, and for each value, a new issue is reported using the provided
     * rule, location, and string representation.
     * <li>Retrieves the file path of the root detection store. This allows the method to identify
     *     and retrieve the assets associated with the root detection values.
     * <li>Translates the detection values into asset values using the provided rootDetectionStore.
     *     The resulting assets are stored in a new List<INode> called rootAssetValues.
     * <li>Handles any child detection stores by recursively traversing the detection store
     *     hierarchy. This ensures that all relevant assets are accounted for during the translation
     *     process.
     * <li>Prints the node tree based on the translated detection values. This allows developers to
     *     visualize the structure and relationships between different nodes in the system.
     * <li>Finally, returns the rootAssetValues list as the output of the method. This allows other
     *     parts of the program to use the translated detection values for further processing or
     *     analysis. <br>
     *
     * @param rootDetectionStore The root detection store containing the initial translation data.
     * @return A list of translated detection values, representing the nodes in the system.
     */
    @Nonnull
    @Override
    public List<INode> translate(
            @Nonnull
                    DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>
                            rootDetectionStore) {

        final String filePath = rootDetectionStore.getScanContext().getRelativePath();
        // get assets of root
        final Map<INode, INode> rootAssetValues =
                rootDetectionStore.getDetectionValues().stream()
                        .map(
                                ivalue ->
                                        translate(
                                                rootDetectionStore.getDetectionRule().bundle(),
                                                ivalue,
                                                rootDetectionStore.getDetectionValueContext(),
                                                filePath))
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .collect(Collectors.toMap(k -> k, n -> n));

        final List<INode> values = rootAssetValues.values().stream().toList();
        if (values.isEmpty()) {
            LOGGER.warn("Detected values of root detection store could not be translated");
            return List.of();
        }

        Map<INode, INode> additionalRootNodes = new ConcurrentHashMap<>();
        // handle children
        rootDetectionStore
                .getChildren()
                .forEach(
                        store ->
                                traversDetectionStores(store, additionalRootNodes, values, values));
        // if the additionalRootNodes list is empty, then we can just return the values
        if (additionalRootNodes.isEmpty()) {
            return values;
        }

        // override existing roots with additional roots
        rootAssetValues.putAll(additionalRootNodes);
        return rootAssetValues.values().stream().toList();
    }

    @SuppressWarnings("java:S3776")
    private void traversDetectionStores(
            @Nonnull
                    final DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>
                            detectionStore,
            @Nonnull final Map<INode, INode> additionalRootNodes,
            @Nonnull @Unmodifiable final List<INode> rootNodes,
            @Nonnull @Unmodifiable final List<INode> parentNodes) {
        if (parentNodes.isEmpty()) {
            throw new UnsupportedOperationException("Set of parent nodes can't be empty");
        }
        final String filePath = detectionStore.getScanContext().getFilePath();
        final List<INode> nodes =
                detectionStore.getDetectionValues().stream()
                        .map(
                                ivalue ->
                                        translate(
                                                detectionStore.getDetectionRule().bundle(),
                                                ivalue,
                                                detectionStore.getDetectionValueContext(),
                                                filePath))
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .toList();
        /*
         * The following code is used to find and add new nodes to the root node. It iterates over all the nodes in
         * the given parentNodes list and checks if any of them have a child node with the same kind as the current
         * node being considered.
         *
         * If such a child exists, it recursively finds all the nodes in the rootNodes list
         * that are connected to the child node and creates a deep copy of the current node. The code then appends
         * the found child node to the copied parent node and adds it to the 'additionalRootNodes' list for further
         * processing.
         *
         * If no such child exists, the current node is simply appended to the parent node. This ensures that all
         * relevant nodes are included in the final root node structure
         */
        for (INode parentNode : parentNodes) {
            for (INode childNode : nodes) {
                if (parentNode.hasChildOfType(childNode.getKind()).isPresent()) {
                    for (INode rootNode : rootNodes) {
                        final INode newRoot = rootNode.deepCopy();
                        final Optional<INode> possibleParentNodeInNodeCopy =
                                newRoot.find(parentNode);
                        if (possibleParentNodeInNodeCopy.isPresent()) {
                            final INode parentNodeInNodeCopy = possibleParentNodeInNodeCopy.get();
                            parentNodeInNodeCopy.append(childNode);
                            additionalRootNodes.put(rootNode, newRoot);
                        }
                    }
                } else {
                    parentNode.append(childNode);
                }
            }
        }
        // Check if the nodes are empty
        if (nodes.isEmpty()) {
            // Call a recursive method to traverse and add detection stores
            detectionStore
                    .getChildren()
                    .forEach(
                            store ->
                                    traversDetectionStores(
                                            store, additionalRootNodes, rootNodes, parentNodes));
        } else {
            // Call a recursive method to traverse and add detection stores
            detectionStore
                    .getChildren()
                    .forEach(
                            store ->
                                    traversDetectionStores(
                                            store, additionalRootNodes, rootNodes, nodes));
        }
    }

    @Nonnull
    public Optional<INode> translate(
            @Nonnull final IBundle bundleIdentifier,
            @Nonnull final IValue<Tree> value,
            @Nonnull final IDetectionContext detectionValueContext,
            @Nonnull final String filePath) {
        DetectionLocation detectionLocation =
                getDetectionContextFrom(value.getLocation(), filePath);
        if (detectionLocation == null) {
            return Optional.empty();
        }

        // cipher context
        if (detectionValueContext.is(CipherContext.class)) {
            JavaCipherContextTranslator javaCipherContextTranslation =
                    new JavaCipherContextTranslator(javaMapperConfig);
            return javaCipherContextTranslation.translate(bundleIdentifier,
                    value, detectionValueContext, detectionLocation);

            // secret key context
        } else if (detectionValueContext.is(SecretKeyContext.class)) {
            KeyContext.Kind kind = ((SecretKeyContext) detectionValueContext).kind();
            JavaSecretKeyContextTranslator javaSecretKeyContextTranslation =
                    new JavaSecretKeyContextTranslator(javaMapperConfig);
            return javaSecretKeyContextTranslation.translate(
                    value, kind, detectionValueContext, detectionLocation);

            // private- / public- / secret- / key context
        } else if (detectionValueContext.is(KeyContext.class)
                || detectionValueContext.is(PublicKeyContext.class)
                || detectionValueContext.is(PrivateKeyContext.class)
                || detectionValueContext.is(SecretKeyContext.class)) {
            KeyContext.Kind kind = ((KeyContext) detectionValueContext).kind();
            JavaKeyContextTranslator javaKeyContextTranslation =
                    new JavaKeyContextTranslator(javaMapperConfig);
            return javaKeyContextTranslation.translate(
                    value, kind, detectionValueContext, detectionLocation);

            // key agreement context
        } else if (detectionValueContext.is(KeyAgreementContext.class)) {
            final JavaKeyAgreementContextTranslator javaKeyAgreementContextTranslator =
                    new JavaKeyAgreementContextTranslator(javaMapperConfig);
            return javaKeyAgreementContextTranslator.translate(
                    value, detectionValueContext, detectionLocation);

            // PRNG context
        } else if (detectionValueContext.is(PRNGContext.class)) {
            JavaPRNGContextTranslator javaPRNGContextTranslation =
                    new JavaPRNGContextTranslator(javaMapperConfig);
            return javaPRNGContextTranslation.translate(
                    value, detectionValueContext, detectionLocation);

            // digest context
        } else if (detectionValueContext.is(DigestContext.class)) {
            DigestContext.Kind kind = ((DigestContext) detectionValueContext).kind();
            JavaDigestContextTranslator javaDigestContextTranslation =
                    new JavaDigestContextTranslator(javaMapperConfig);
            return javaDigestContextTranslation.translate(
                    value, kind, detectionValueContext, detectionLocation);

            // signature context
        } else if (detectionValueContext.is(SignatureContext.class)) {
            SignatureContext.Kind kind = ((SignatureContext) detectionValueContext).kind();
            JavaSignatureContextTranslator javaSignatureContextTranslation =
                    new JavaSignatureContextTranslator(javaMapperConfig);
            return javaSignatureContextTranslation.translate(
                    value, kind, detectionValueContext, detectionLocation);

            // mac context
        } else if (detectionValueContext.is(MacContext.class)) {
            MacContext.Kind kind = ((MacContext) detectionValueContext).kind();
            JavaMacContextTranslator javaMacContextTranslation =
                    new JavaMacContextTranslator(javaMapperConfig);
            return javaMacContextTranslation.translate(
                    value, kind, detectionValueContext, detectionLocation);

            // algorithm parameter context
        } else if (detectionValueContext.is(AlgorithmParameterContext.class)) {
            AlgorithmParameterContext.Kind kind =
                    ((AlgorithmParameterContext) detectionValueContext).kind();
            JavaAlgorithmParameterContextTranslator javaAlgorithmParameterContextTranslation =
                    new JavaAlgorithmParameterContextTranslator(javaMapperConfig);
            return javaAlgorithmParameterContextTranslation.translate(
                    value, kind, detectionValueContext, detectionLocation);

            // protocol
        } else if (detectionValueContext.is(ProtocolContext.class)) {
            final ProtocolContext.Kind kind = ((ProtocolContext) detectionValueContext).kind();
            final JavaProtocolContextTranslator javaProtocolContextTranslator =
                    new JavaProtocolContextTranslator(javaMapperConfig);
            return javaProtocolContextTranslator.translate(
                    value, kind, detectionValueContext, detectionLocation);
        }
        return Optional.empty();
    }

    /**
     * This function gets a detection context from the specified Tree location and file path. <br>
     * <li>It retrieves the first and last tokens in the location, checks if both are not null, and
     *     then extracts the range of the first token. From this, it obtains the line number and
     *     offset.
     * <li>It also determines the kind of the location (e.g., NEW_CLASS, METHOD_INVOCATION,
     *     ENUM_CONSTANT) and populates a list of keywords accordingly.
     * <li>Finally, it creates a new DetectionContext object using the obtained information and
     *     returns it. If any of the conditions are not met or if an error occurs during the
     *     process, it returns null.
     */
    @Nullable public DetectionLocation getDetectionContextFrom(
            @Nonnull Tree location, @Nonnull String filePath) {
        SyntaxToken firstToken = location.firstToken();
        SyntaxToken lastToken = location.lastToken();
        if (firstToken != null && lastToken != null) {
            Range rangeFirst = firstToken.range();
            Position start = rangeFirst.start();
            int lineNumber = start.line();
            int offset = start.columnOffset();
            List<String> keywords = List.of();
            switch (location.kind()) {
                case NEW_CLASS:
                    keywords =
                            List.of(
                                    ((NewClassTree) location).methodSymbol().signature(),
                                    ((NewClassTree) location).methodSymbol().name(),
                                    ((NewClassTree) location).identifier().toString());
                    break;
                case METHOD_INVOCATION:
                    keywords =
                            List.of(
                                    ((MethodInvocationTree) location).methodSymbol().signature(),
                                    ((MethodInvocationTree) location).methodSymbol().name());
                    break;
                case ENUM_CONSTANT:
                    keywords =
                            List.of(
                                    ((EnumConstantTree) location)
                                            .initializer()
                                            .methodSymbol()
                                            .signature(),
                                    ((EnumConstantTree) location)
                                            .initializer()
                                            .methodSymbol()
                                            .name());
                    break;
                default:
                    // nothing
            }
            return new DetectionLocation(filePath, lineNumber, offset, keywords);
        }
        return null;
    }
}
