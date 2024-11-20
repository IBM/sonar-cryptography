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
package com.ibm.rules.issue;

import com.ibm.mapper.model.INode;
import com.ibm.rules.builder.IFunctionMatchCondition;
import com.ibm.rules.builder.IFunctionReport;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class IssueCreator<T> {
    @Nonnull private final List<INode> nodes;
    @Nonnull private final T markedTree;
    @Nonnull private final Set<INode> matchedNodes;
    @Nullable private final INode matchedParentNode;

    private IssueCreator(@Nonnull List<INode> nodes, @Nonnull T markedTree) {
        this.nodes = nodes;
        this.markedTree = markedTree;
        this.matchedNodes = new HashSet<>();
        this.matchedParentNode = null;
    }

    private IssueCreator(
            @Nonnull List<INode> nodes,
            @Nonnull T markedTree,
            @Nonnull Set<INode> matchedNodes,
            @Nullable INode matchedParentNode) {
        this.nodes = nodes;
        this.markedTree = markedTree;
        this.matchedNodes = matchedNodes;
        this.matchedParentNode = matchedParentNode;
    }

    @Nonnull
    public static <T> IssueCreator<T> using(@Nonnull T markedTree, @Nonnull List<INode> nodes) {
        return new IssueCreator<>(nodes, markedTree);
    }

    @Nonnull
    public IssueCreator<T> matchesCondition(@Nonnull IFunctionMatchCondition condition) {
        return matchesCondition(condition, this.nodes, null);
    }

    @Nonnull
    private IssueCreator<T> matchesCondition(
            @Nonnull IFunctionMatchCondition condition,
            @Nonnull List<INode> currentNodes,
            @Nullable INode parentNode) {
        final Set<INode> newMatchedNodes = new HashSet<>();
        for (final INode node : currentNodes) {
            if (condition.apply(node, parentNode)) {
                newMatchedNodes.add(node);
            }

            if (!node.getChildren().isEmpty()) {
                final IssueCreator<T> recursiveCreator =
                        matchesCondition(
                                condition, node.getChildren().values().stream().toList(), node);
                newMatchedNodes.addAll(recursiveCreator.matchedNodes);
            }
        }
        return new IssueCreator<>(nodes, markedTree, newMatchedNodes, null);
    }

    @Nonnull
    public List<Issue<T>> create(@Nonnull IFunctionReport<T> report) {
        final List<Issue<T>> issues = new ArrayList<>();
        for (final INode node : matchedNodes) {
            issues.add(report.apply(this.markedTree, node, this.matchedParentNode));
        }
        return issues;
    }
}
