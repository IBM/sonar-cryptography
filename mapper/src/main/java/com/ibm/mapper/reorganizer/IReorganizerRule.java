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
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface IReorganizerRule {

    /**
     * For a given {@code node}, check if it matches with the full pattern defined by the rule
     *
     * @param node - The top node that matched with the rule
     * @param parent - The parent node of {@code node}, or {@code null} if node is a root node
     * @param roots - The list of root nodes for the translation tree
     * @return A boolean stating if there is a match or not
     */
    boolean match(@Nonnull INode node, @Nonnull INode parent, @Nonnull List<INode> roots);

    /**
     * Apply the reorganization defined in the {@code perform} function of the rule
     *
     * @param node - The top node that matched with the rule
     * @param parent - The parent node of {@code node}, or {@code null} if node is a root node
     * @param roots - The list of root nodes for the translation tree
     * @return An updated list of root nodes for the translation tree
     */
    @Nullable List<INode> applyReorganization(
            @Nonnull INode node, @Nonnull INode parent, @Nonnull List<INode> roots);

    @Nonnull
    String asString();

    @Nonnull
    Class<? extends INode> getNodeKind();

    /*
     * Builder pattern:
     *  - `[...]` represents optional builder statements
     *  - `A || B` tells that *only* one of the two statements can be applied
     *
     * new ReorganizerRuleBuilder()
     *      .createReorganizerRule()
     *      .forNodeKind(kind)
     *      [.forNodeValue(value)]
     *      [.includingChildren(children) || .withAnyNonNullChildren()]
     *      [.withDetectionCondition(detectionConditionFunction)]
     *      .perform(performFunction) || .noAction()
     */

    interface IReorganizerRuleBuilder {
        @Nonnull
        KindBuilder createReorganizerRule();

        @Nonnull
        KindBuilder createReorganizerRule(@Nonnull String ruleName);
    }

    interface KindBuilder {
        @Nonnull
        ValueBuilder forNodeKind(@Nonnull Class<? extends INode> kind);
    }

    interface ValueBuilder {
        @Nonnull
        ChildrenBuilder forNodeValue(@Nonnull String value);

        @Nonnull
        DetectionConditionBuilder includingChildren(@Nonnull List<IReorganizerRule> children);

        @Nonnull
        DetectionConditionBuilder withAnyNonNullChildren();

        @Nonnull
        PerformBuilder withDetectionCondition(
                @Nonnull IFunctionDetectionCondition detectionConditionFunction);

        @Nonnull
        IReorganizerRule perform(@Nonnull IFunctionPerformReorganization performFunction);

        @Nonnull
        IReorganizerRule noAction();
    }

    interface ChildrenBuilder {
        @Nonnull
        DetectionConditionBuilder includingChildren(@Nonnull List<IReorganizerRule> children);

        @Nonnull
        DetectionConditionBuilder withAnyNonNullChildren();

        @Nonnull
        PerformBuilder withDetectionCondition(
                @Nonnull IFunctionDetectionCondition detectionConditionFunction);

        @Nonnull
        IReorganizerRule perform(@Nonnull IFunctionPerformReorganization performFunction);

        @Nonnull
        IReorganizerRule noAction();
    }

    interface DetectionConditionBuilder {
        @Nonnull
        PerformBuilder withDetectionCondition(
                @Nonnull IFunctionDetectionCondition detectionConditionFunction);

        @Nonnull
        IReorganizerRule perform(@Nonnull IFunctionPerformReorganization performFunction);

        @Nonnull
        IReorganizerRule noAction();
    }

    interface PerformBuilder {
        @Nonnull
        IReorganizerRule perform(@Nonnull IFunctionPerformReorganization performFunction);

        @Nonnull
        IReorganizerRule noAction();
    }
}
