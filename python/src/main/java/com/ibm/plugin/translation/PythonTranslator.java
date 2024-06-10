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

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.*;
import com.ibm.engine.model.context.*;
import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.*;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.plugin.translation.contexts.PythonCipherContextTranslator;
import com.ibm.plugin.translation.contexts.PythonDigestContextTranslator;
import com.ibm.plugin.translation.contexts.PythonKeyContextTranslator;
import com.ibm.plugin.translation.contexts.PythonMacContextTranslator;
import com.ibm.plugin.translation.contexts.PythonPrivateKeyContextTranslator;
import com.ibm.plugin.translation.contexts.PythonPublicKeyContextTranslator;
import com.ibm.plugin.translation.contexts.PythonSecretKeyContextTranslator;
import com.ibm.plugin.translation.contexts.PythonSignatureContextTranslator;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.CallExpression;
import org.sonar.plugins.python.api.tree.Name;
import org.sonar.plugins.python.api.tree.Token;
import org.sonar.plugins.python.api.tree.Tree;

public class PythonTranslator extends ITranslator<PythonCheck, Tree, Symbol, PythonVisitorContext> {

    @Nonnull private final PythonMapperConfig pythonMapperConfig = new PythonMapperConfig();

    public PythonTranslator(@Nonnull PythonCheck rule) {
        super(rule);
    }

    /**
     * The translate method is responsible for translating the provided detection store. It performs
     * several important tasks within its implementation: <br>
     * <li>Reports issues based on the root detection values. The rootDetectionStore is used to
     *     retrieve the detection values, and for each value, a new issue is reported using the
     *     provided rule, location, and string representation.
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
                    DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>
                            rootDetectionStore) {
        // report issue
        rootDetectionStore
                .getDetectionValues()
                .forEach(
                        iValue ->
                                rootDetectionStore
                                        .getScanContext()
                                        .reportIssue(
                                                rule, iValue.getLocation(), iValue.asString()));
        // get assets of root
        final String filePath = rootDetectionStore.getScanContext().getRelativePath();

        List<INode> values = new LinkedList<>(); // Root translated values

        // 1. We look at the root action value
        Optional<IAction<Tree>> actionValue = rootDetectionStore.getActionValue();
        if (actionValue.isPresent()) {
            Optional<INode> translatedActionValue =
                    translate(
                            actionValue.get(),
                            rootDetectionStore.getDetectionValueContext(),
                            filePath);
            // Add translated root action value
            translatedActionValue.ifPresent(values::add);
        }

        Map<INode, INode> additionalRootNodes = new ConcurrentHashMap<>();
        List<Integer> exploredValueIndexes = new LinkedList<>();

        // 2. We look at the parameters detections
        rootDetectionStore.detectionValuesForEachParameter(
                (parameterIndex, valuesList) -> {
                    exploredValueIndexes.add(parameterIndex);

                    final List<INode> nodes =
                            valuesList.stream()
                                    .map(
                                            ivalue ->
                                                    translate(
                                                            ivalue,
                                                            rootDetectionStore
                                                                    .getDetectionValueContext(),
                                                            filePath))
                                    .filter(Optional::isPresent)
                                    .map(Optional::get)
                                    .toList();

                    // Check if the nodes are not empty
                    if (!nodes.isEmpty()) {
                        rootDetectionStore.childrenForEachParameter(
                                (childIndex, childDetectionStores) -> {
                                    if (parameterIndex.equals(childIndex)) {
                                        childDetectionStores.forEach(
                                                store ->
                                                        traversDetectionStores(
                                                                store,
                                                                additionalRootNodes,
                                                                nodes,
                                                                nodes));
                                    }
                                });
                    }

                    // Add translated root parameter detection values
                    values.addAll(nodes);
                });

        // 3. We now look at the parameters that did not have any detections
        rootDetectionStore.childrenForEachParameter(
                (childIndex, childDetectionStores) -> {
                    if (!exploredValueIndexes.contains(childIndex)) {
                        childDetectionStores.forEach(
                                store ->
                                        traversDetectionStores(
                                                store, additionalRootNodes, values, values));
                    }
                });

        // 4. Finally, we look at the method depending detection rule
        rootDetectionStore
                .getChildrenForMethod()
                .forEach(
                        store ->
                                traversDetectionStores(store, additionalRootNodes, values, values));

        // TODO: are `additionalRootNodes` in Python?
        // 5. Enrich the tree of translated nodes
        List<INode> enrichedValues = enrich(values, true);

        // TODO: refactor Python's translation process

        return enrichedValues;
    }

    private List<INode> enrich(@Nonnull final List<INode> values, boolean isRoot) {
        List<INode> newValues = new ArrayList<>(values);
        final PythonEnricher enricher = new PythonEnricher();
        if (isRoot) {
            newValues = enricher.enrichRootBefore(values);
        }
        Map<Class<? extends INode>, INode> nodesMap =
                newValues.stream().collect(Collectors.toMap(INode::getKind, n -> n));
        nodesMap.forEach((k, v) -> enricher.enrich(v));
        nodesMap.forEach(
                (k, v) -> {
                    if (v.hasChildren()) {
                        enrich(v.getChildren().values().stream().toList(), false);
                    }
                });
        if (isRoot) {
            newValues = enricher.enrichRootAfter(newValues);
        }
        return newValues;
    }

    /**
     * When the {@code parentNode} has no child of the kind of {@code childNode}, simply append
     * {@code childNode} to {@code parentNode}. Otherwise, instead of immediately replacing the
     * current child of {@code parentNode} by {@code childNode}, add all grandchildren of the
     * current child to {@code childNode} before replacing it.
     *
     * @param parentNode
     * @param childNode
     */
    private void softAppend(@Nonnull INode parentNode, @Nonnull INode childNode) {
        if (parentNode.hasChildOfType(childNode.getKind()).isPresent()) {
            INode existingChildNode = parentNode.getChildren().get(childNode.getKind());
            for (INode grandChildNode : existingChildNode.getChildren().values()) {
                childNode.append(grandChildNode);
            }
            parentNode.append(childNode);
        } else {
            parentNode.append(childNode);
        }
    }

    private void traversDetectionStores(
            @Nonnull
                    final DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>
                            detectionStore,
            @Nonnull final Map<INode, INode> additionalRootNodes,
            @Nonnull @Unmodifiable final List<INode> rootNodes,
            @Nonnull @Unmodifiable final List<INode> parentNodes) {
        if (parentNodes.isEmpty()) {
            throw new UnsupportedOperationException("Set of parent nodes can't be empty");
        }

        final String filePath = detectionStore.getScanContext().getFilePath();
        List<INode> parentNodesLocal = parentNodes;

        // If the detection store has an actionValue (a top level `shouldBeDetectedAs`), append the
        // detected value to the current parrent and make the value the new parent for the following
        // parameters detections
        Optional<IAction<Tree>> actionValueOptional = detectionStore.getActionValue();
        if (actionValueOptional.isPresent()) {
            IAction<Tree> actionValue = actionValueOptional.get();
            final List<INode> methodNodes =
                    Stream.of(actionValue)
                            .map(
                                    value ->
                                            translate(
                                                    value,
                                                    detectionStore.getDetectionValueContext(),
                                                    filePath))
                            .filter(Optional::isPresent)
                            .map(Optional::get)
                            .toList();

            for (INode parentNode : parentNodes) {
                for (INode methodNode : methodNodes) {
                    softAppend(parentNode, methodNode);
                }
            }

            parentNodesLocal = methodNodes;
        }

        // The updated parent list to used for the following parameters detections
        final List<INode> parentNodesLocalFinal = parentNodesLocal;

        // 1. We look at the parameters detections (with a `shouldBeDetectedAs`), and we keep track
        // of the parameters of these indexes for later in `exploredValueIndexes`
        List<Integer> exploredValueIndexes = new LinkedList<>();
        detectionStore.detectionValuesForEachParameter(
                (parameterIndex, valuesList) -> {
                    exploredValueIndexes.add(parameterIndex);

                    final List<INode> nodes =
                            valuesList.stream()
                                    .map(
                                            ivalue ->
                                                    translate(
                                                            ivalue,
                                                            detectionStore
                                                                    .getDetectionValueContext(),
                                                            filePath))
                                    .filter(Optional::isPresent)
                                    .map(Optional::get)
                                    .toList();

                    // We append translated values `nodes` to the parent node(s)
                    for (INode parentNode : parentNodesLocalFinal) {
                        for (INode childNode : nodes) {
                            softAppend(parentNode, childNode);
                        }
                    }

                    // Check if the nodes are empty, we translate the following rules (defined in
                    // `childDetectionStores`) and use the current parent to append these next
                    // results
                    if (nodes.isEmpty()) {
                        // If the translation didn't return `nodes`
                        detectionStore.childrenForEachParameter(
                                (childIndex, childDetectionStores) -> {
                                    if (Objects.equals(parameterIndex, childIndex)) {
                                        childDetectionStores.forEach(
                                                store ->
                                                        traversDetectionStores(
                                                                store,
                                                                additionalRootNodes,
                                                                rootNodes,
                                                                parentNodesLocalFinal));
                                    }
                                });
                    } else {
                        // If the translation returned nodes, we translate the following rules
                        // (defined in `childDetectionStores`) and append the next results to these
                        // returned nodes
                        detectionStore.childrenForEachParameter(
                                (childIndex, childDetectionStores) -> {
                                    if (Objects.equals(parameterIndex, childIndex)) {
                                        childDetectionStores.forEach(
                                                store ->
                                                        traversDetectionStores(
                                                                store,
                                                                additionalRootNodes,
                                                                rootNodes,
                                                                nodes)); // `nodes` is the new
                                        // parent
                                    }
                                });
                    }
                });

        // 2. We now look at the parameters that did not have any detections (no
        // `shouldBeDetectedAs`): those are the indexes not in `exploredValueIndexes`
        // They may still have depending detection rules!
        // So we translate the following rules (defined in `childDetectionStores`) and use the
        // current parent to append these next results
        detectionStore.childrenForEachParameter(
                (childIndex, childDetectionStores) -> {
                    if (!exploredValueIndexes.contains(childIndex)) {
                        childDetectionStores.forEach(
                                store ->
                                        traversDetectionStores(
                                                store,
                                                additionalRootNodes,
                                                rootNodes,
                                                parentNodesLocalFinal));
                    }
                });

        // 3. Finally, if there is a method depending rule (defined with
        // `withDependingDetectionRules`), we translate it and use the current parent to append
        // these next results
        detectionStore
                .getChildrenForMethod()
                .forEach(
                        store ->
                                traversDetectionStores(
                                        store,
                                        additionalRootNodes,
                                        rootNodes,
                                        parentNodesLocalFinal));
    }

    @Nonnull
    public Optional<INode> translate(
            @Nonnull final IValue<Tree> value,
            @Nonnull final IDetectionContext detectionValueContext,
            @Nonnull final String filePath) {
        DetectionLocation detectionLocation =
                getDetectionContextFrom(value.getLocation(), filePath);
        if (detectionLocation == null) {
            return Optional.empty();
        }

        if (detectionValueContext.is(KeyContext.class)) {
            KeyContext.Kind detectionValueContextKind = ((KeyContext) detectionValueContext).kind();
            return PythonKeyContextTranslator.translateForKeyContext(
                    value, detectionValueContextKind, detectionLocation);
        }
        if (detectionValueContext.is(PrivateKeyContext.class)) {
            KeyContext.Kind detectionValueContextKind = ((KeyContext) detectionValueContext).kind();
            return PythonPrivateKeyContextTranslator.translateForPrivateKeyContext(
                    value, detectionValueContextKind, detectionLocation);

        } else if (detectionValueContext.is(SecretKeyContext.class)) {
            KeyContext.Kind detectionValueContextKind = ((KeyContext) detectionValueContext).kind();
            return PythonSecretKeyContextTranslator.translateForSecretKeyContext(
                    value, detectionValueContextKind, detectionLocation);

        } else if (detectionValueContext.is(PublicKeyContext.class)) {
            KeyContext.Kind detectionValueContextKind = ((KeyContext) detectionValueContext).kind();
            return PythonPublicKeyContextTranslator.translateForPublicKeyContext(
                    value, detectionValueContextKind, detectionLocation);

        } else if (detectionValueContext.is(DigestContext.class)) {
            DigestContext.Kind detectionValueContextKind =
                    ((DigestContext) detectionValueContext).kind();
            return PythonDigestContextTranslator.translateForDigestContext(
                    value, detectionValueContextKind, detectionLocation);

        } else if (detectionValueContext.is(SignatureContext.class)) {
            SignatureContext.Kind detectionValueContextKind =
                    ((SignatureContext) detectionValueContext).kind();
            return PythonSignatureContextTranslator.translateForSignatureContext(
                    value, detectionValueContextKind, detectionLocation);

        } else if (detectionValueContext.is(CipherContext.class)) {
            CipherContext.Kind detectionValueContextKind =
                    ((CipherContext) detectionValueContext).kind();
            return PythonCipherContextTranslator.translateForCipherContext(
                    value, detectionValueContextKind, detectionLocation);

        } else if (detectionValueContext.is(MacContext.class)) {
            MacContext.Kind detectionValueContextKind = ((MacContext) detectionValueContext).kind();
            return PythonMacContextTranslator.translateForMacContext(
                    value, detectionValueContextKind, detectionLocation);
        }

        return Optional.empty();
    }

    /**
     * This function gets a detection context from the specified Tree location and file path. <br>
     * <li>It obtains the line number and offset.
     * <li>It also determines the kind of the location and populates a list of keywords accordingly.
     * <li>Finally, it creates a new DetectionContext object using the obtained information and
     *     returns it. If any of the conditions are not met or if an error occurs during the
     *     process, it returns null.
     */
    @Nullable public DetectionLocation getDetectionContextFrom(
            @Nonnull Tree location, @Nonnull String filePath) {
        Token firstToken = location.firstToken();
        Token lastToken = location.lastToken();
        if (firstToken != null && lastToken != null) {
            int lineNumber = firstToken.line();
            int offset = firstToken.column();
            List<String> keywords = List.of();
            if (location.getKind() == Tree.Kind.CALL_EXPR) {
                final CallExpression callExpression = (CallExpression) location;
                final Symbol callSymbol = callExpression.calleeSymbol();
                if (callSymbol != null) {
                    keywords = List.of(callSymbol.name());
                } else if (callExpression.callee() instanceof Name nameTree) {
                    keywords = List.of(nameTree.name());
                }
            }
            return new DetectionLocation(filePath, lineNumber, offset, keywords);
        }
        return null;
    }
}
