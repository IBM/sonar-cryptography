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
package com.ibm.mapper.reorganizer;

import com.ibm.mapper.model.INode;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.apache.commons.lang3.tuple.Pair;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Reorganizer implements IReorganizer {
    private static final Logger LOGGER = LoggerFactory.getLogger(Reorganizer.class);

    // Maximum number of reorganization steps (to prevent infinite loops)
    private static final int MAX_ITERATIONS = 10;

    private final List<IReorganizerRule> rules;

    public Reorganizer(@Nonnull List<IReorganizerRule> rules) {
        this.rules = rules;
    }

    @Override
    @Nonnull
    public List<INode> reorganize(@Nonnull final List<INode> rootNodes) {
        /*
         * Idea: We iterate on all nodes of the tree with a BFS (done by `reorganizeRecursive`),
         * and we check for each node if it matches with a reorganization rule (in `applyReorganizerRules`).
         * If it matches, we apply the reorganization and return the updated list of root nodes of the
         * translation tree. We stop the BFS and start the process again by iterating on all nodes of
         * starting from the new roots.
         * This process ends once no reorganization rule matches with the current translation tree. When
         * this is the case, `reorganizeRecursive` returns an empty Optional, which is our condition to
         * stop the while loop defined in `reorganize`.
         */
        List<INode> lastRootNodes = rootNodes;
        Optional<List<INode>> newRootNodes = Optional.of(rootNodes);
        int counter = 0;
        while (newRootNodes.isPresent() && counter < MAX_ITERATIONS) {
            lastRootNodes = newRootNodes.get();
            newRootNodes =
                    reorganizeRecursive(
                            lastRootNodes.stream()
                                    .map(childNode -> Pair.<INode, INode>of(childNode, null))
                                    .toList(),
                            lastRootNodes);
            counter += 1;
        }
        if (counter == MAX_ITERATIONS) {
            String message =
                    String.format(
                            "The reorganizer stopped because it exceeded the maximum number of iterations (%d). "
                                    + "Check for a possible infinite loop in your reorganization rules.",
                            MAX_ITERATIONS);
            LOGGER.warn(message);
        }
        return lastRootNodes;
    }

    /**
     * Check the given nodes for a match with reorganizer rules, and apply the reorganization of the
     * first match. If no match happens, recursively continue with the children of all the nodes.
     *
     * @param currentNodeParentPairs - Pairs of nodes with their parent node (if a node is a root
     *     node, its parent is {@code null})
     * @param rootNodes - Root nodes of the translation tree
     * @return Optional containing the new root nodes of the translation tree if a reorganization
     *     has occured, empty Optional otherwise
     */
    @Nonnull
    private Optional<List<INode>> reorganizeRecursive(
            @Nonnull final List<Pair<INode, INode>> currentNodeParentPairs,
            @Nonnull final List<INode> rootNodes) {
        List<Pair<INode, INode>> nextPairs = new LinkedList<>();

        for (Pair<INode, INode> pair : currentNodeParentPairs) {
            INode node = pair.getLeft();
            INode parent = pair.getRight();
            Optional<List<INode>> optionalUpdatedRootNodes =
                    applyReorganizerRules(node, parent, rootNodes);
            if (optionalUpdatedRootNodes.isPresent()) {
                return optionalUpdatedRootNodes;
            }
            nextPairs.addAll(
                    node.getChildren().values().stream()
                            .map(childNode -> Pair.of(childNode, node))
                            .toList());
        }
        if (nextPairs.isEmpty()) {
            return Optional.empty();
        }
        return reorganizeRecursive(nextPairs, rootNodes);
    }

    /**
     * Check if {@code node} matches with any reorganization rule, and apply the reorganization of
     * the first match.
     *
     * @param node - the current node
     * @param parent - Parent of {@code node}, or {@code null} if {@code node} is a root node
     * @param rootNodes - Root nodes of the translation tree
     * @return Optional containing the new root nodes of the translation tree if a reorganization
     *     has occured, empty Optional otherwise
     */
    @Nonnull
    private Optional<List<INode>> applyReorganizerRules(
            @Nonnull INode node, @Nonnull INode parent, @Nonnull final List<INode> rootNodes) {
        for (IReorganizerRule reorganizerRule : this.rules) {
            if (reorganizerRule.match(node, parent, rootNodes)) {
                String message =
                        String.format(
                                "[reorganizer] MATCH: Node '%s' & Rule %s",
                                node.asString(), reorganizerRule.asString());
                LOGGER.debug(message);
                return Optional.ofNullable(
                        reorganizerRule.applyReorganization(node, parent, rootNodes)); // new root
            }
        }

        return Optional.empty();
    }
}
