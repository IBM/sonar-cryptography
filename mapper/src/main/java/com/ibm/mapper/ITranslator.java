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
package com.ibm.mapper;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The translation method is responsible for translating the provided detection store. It performs
 * several important tasks within its implementation: <br>
 * retrieve the detection values, and for each value, a new issue is reported using the provided
 * rule, location, and string representation.
 * <li>Retrieves the file path of the root detection store. This allows the method to identify and
 *     retrieve the assets associated with the root detection values.
 * <li>Translates the detection values into asset values using the provided rootDetectionStore. The
 *     resulting assets are stored in a new List<INode> called rootAssetValues.
 * <li>Handles any child detection stores by recursively traversing the detection store hierarchy.
 *     This ensures that all relevant assets are accounted for during the translation process.
 * <li>Prints the node tree based on the translated detection values. This allows developers to
 *     visualize the structure and relationships between different nodes in the system.
 * <li>Finally, returns the rootAssetValues list as the output of the method. This allows other
 *     parts of the program to use the translated detection values for further processing or
 *     analysis. <br>
 */
public abstract class ITranslator<R, T, S, P> {

    public static final String UNKNOWN = "unknown";

    @Nonnull
    public List<INode> translate(@Nonnull DetectionStore<R, T, S, P> rootDetectionStore) {
        final Map<Integer, List<INode>> rootNodes = translateStore(rootDetectionStore);
        travers(rootDetectionStore, rootNodes);
        return rootNodes.values().stream().flatMap(List::stream).toList();
    }

    private void travers(
            @Nonnull DetectionStore<R, T, S, P> store,
            @Nonnull Map<Integer, List<INode>> parentNodes) {
        store.getChildrenForMethod().forEach(child -> translateAndAppend(-1, child, parentNodes));
        store.childrenForEachParameter(
                (id, children) -> {
                    for (DetectionStore<R, T, S, P> child : children) {
                        translateAndAppend(id, child, parentNodes);
                    }
                });
    }

    private void translateAndAppend(
            int id,
            @Nonnull DetectionStore<R, T, S, P> child,
            @Nonnull Map<Integer, List<INode>> parentNodes) {
        Map<Integer, List<INode>> nodes = translateStore(child);
        // collect nodes and add to parent
        final List<INode> collection = nodes.values().stream().flatMap(List::stream).toList();
        Optional.ofNullable(parentNodes.get(id))
                .ifPresentOrElse(
                        parents -> parents.forEach(p -> collection.forEach(p::append)),
                        () -> {
                            if (parentNodes.isEmpty()) {
                                parentNodes.put(-1, collection);
                            } else {
                                parentNodes.values().stream()
                                        .findFirst()
                                        .ifPresent(
                                                parents ->
                                                        parents.forEach(
                                                                p ->
                                                                        collection.forEach(
                                                                                p::append)));
                            }
                        });
        if (nodes.isEmpty()) {
            nodes = parentNodes;
        }
        // next iteration
        travers(child, nodes);
    }

    @Nonnull
    private Map<Integer, List<INode>> translateStore(@Nonnull DetectionStore<R, T, S, P> store) {
        final String filePath = store.getScanContext().getRelativePath();
        final IBundle bundle = store.getDetectionRule().bundle();
        final IDetectionContext context = store.getDetectionValueContext();

        final Map<Integer, List<INode>> nodes = new HashMap<>();
        store.getActionValue()
                .ifPresent(
                        actionValue -> {
                            final Optional<INode> translatedNode =
                                    translate(bundle, actionValue, context, filePath);
                            translatedNode.ifPresent(
                                    node -> {
                                        final List<INode> newNodes = new ArrayList<>();
                                        newNodes.add(node);
                                        nodes.put(-1, newNodes);
                                    });
                        });
        store.detectionValuesForEachParameter(
                (id, values) -> {
                    final List<INode> translatedNodesForId = new ArrayList<>();
                    for (IValue<T> value : values) {
                        final Optional<INode> translatedNode =
                                translate(bundle, value, context, filePath);
                        translatedNode.ifPresent(translatedNodesForId::add);
                    }
                    nodes.computeIfAbsent(id, n -> new ArrayList<>()).addAll(translatedNodesForId);
                });
        return nodes;
    }

    @Nonnull
    protected abstract Optional<INode> translate(
            @Nonnull final IBundle bundleIdentifier,
            @Nonnull IValue<T> value,
            @Nonnull IDetectionContext detectionValueContext,
            @Nonnull final String filePath);

    @Nullable protected abstract DetectionLocation getDetectionContextFrom(
            @Nonnull T location, @Nonnull final IBundle bundle, @Nonnull String filePath);
}
