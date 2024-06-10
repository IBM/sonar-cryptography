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
package com.ibm.mapper.reorganizer.builder;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.IReorganizerRule.ChildrenBuilder;
import com.ibm.mapper.reorganizer.IReorganizerRule.DetectionConditionBuilder;
import com.ibm.mapper.reorganizer.IReorganizerRule.PerformBuilder;
import com.ibm.mapper.reorganizer.IReorganizerRule.ValueBuilder;
import com.ibm.mapper.reorganizer.ReorganizerRule;
import com.ibm.mapper.utils.Function3;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

final class ReorganizerRuleBuilderImpl
        implements IReorganizerRule.KindBuilder,
                IReorganizerRule.ValueBuilder,
                IReorganizerRule.ChildrenBuilder,
                IReorganizerRule.DetectionConditionBuilder,
                IReorganizerRule.PerformBuilder {

    @Nullable private Class<? extends INode> kind;
    @Nullable private String value;
    @Nonnull private List<IReorganizerRule> children = new LinkedList<>();
    @Nonnull private boolean nonNullChildren = false;
    @Nullable private Function3<INode, INode, List<INode>, List<INode>> performFunction;
    @Nullable private Function3<INode, INode, List<INode>, Boolean> detectionConditionFunction;

    public ReorganizerRuleBuilderImpl() {}

    public ReorganizerRuleBuilderImpl(
            @Nullable Class<? extends INode> kind,
            @Nullable String value,
            @Nonnull List<IReorganizerRule> children,
            @Nonnull boolean nonNullChildren,
            @Nullable Function3<INode, INode, List<INode>, Boolean> detectionConditionFunction) {
        if (kind != null) {
            this.kind = kind;
        }
        if (value != null) {
            this.value = value;
        }
        this.children = children;
        this.nonNullChildren = nonNullChildren;
        if (detectionConditionFunction != null) {
            this.detectionConditionFunction = detectionConditionFunction;
        }
    }

    @Override
    @Nonnull
    public ValueBuilder forNodeKind(@Nonnull Class<? extends INode> kind) {
        this.kind = kind;
        return new ReorganizerRuleBuilderImpl(
                kind, value, children, nonNullChildren, detectionConditionFunction);
    }

    @Override
    @Nonnull
    public ChildrenBuilder forNodeValue(@Nonnull String value) {
        this.value = value;
        return new ReorganizerRuleBuilderImpl(
                kind, value, children, nonNullChildren, detectionConditionFunction);
    }

    @Override
    @Nonnull
    public DetectionConditionBuilder includingChildren(@Nonnull List<IReorganizerRule> children) {
        this.children = children;
        return new ReorganizerRuleBuilderImpl(
                kind, value, children, nonNullChildren, detectionConditionFunction);
    }

    @Override
    @Nonnull
    public DetectionConditionBuilder withAnyNonNullChildren() {
        this.nonNullChildren = true;
        return new ReorganizerRuleBuilderImpl(
                kind, value, children, nonNullChildren, detectionConditionFunction);
    }

    @Override
    @Nonnull
    public PerformBuilder withDetectionCondition(
            Function3<INode, INode, List<INode>, Boolean> detectionConditionFunction) {
        this.detectionConditionFunction = detectionConditionFunction;
        return new ReorganizerRuleBuilderImpl(
                kind, value, children, nonNullChildren, detectionConditionFunction);
    }

    @Override
    @Nonnull
    public IReorganizerRule perform(
            @Nonnull Function3<INode, INode, List<INode>, List<INode>> performFunction) {
        this.performFunction = performFunction;
        return build();
    }

    @Override
    @Nonnull
    public IReorganizerRule noAction() {
        this.performFunction = null;
        return build();
    }

    @Nonnull
    private IReorganizerRule build() {
        final String err = "ReorganizerRule need to be fully initialized.";
        if (this.kind == null) {
            throw new IllegalStateException(err);
        }

        return new ReorganizerRule(
                kind,
                value,
                children,
                nonNullChildren,
                detectionConditionFunction,
                performFunction);
    }
}
