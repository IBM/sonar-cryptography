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
import com.ibm.mapper.utils.Function3;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public record ReorganizerRule(
        @Nullable String name,
        @Nonnull Class<? extends INode> kind,
        @Nullable String value,
        @Nonnull List<IReorganizerRule> children,
        boolean nonNullChildren,
        @Nullable Function3<INode, INode, List<INode>, Boolean> detectionConditionFunction,
        @Nullable Function3<INode, INode, List<INode>, List<INode>> performFunction)
        implements IReorganizerRule {

    @Override
    public boolean match(@Nonnull INode node, @Nonnull INode parent, @Nonnull List<INode> roots) {
        // Kind check
        if (!node.is(kind)) {
            return false;
        }

        // Name check
        if (value != null && !value.equals(node.asString())) {
            return false;
        }

        // Children check
        if (nonNullChildren && node.getChildren().isEmpty()) {
            return false;
        }
        for (IReorganizerRule childRule : children) {
            Class<? extends INode> childKind = childRule.getNodeKind();

            if (!node.getChildren().containsKey(childKind)) {
                return false;
            }

            if (!childRule.match(node.getChildren().get(childKind), node, roots)) {
                return false;
            }
        }
        // Detection condition check
        return detectionConditionFunction == null
                || detectionConditionFunction.apply(node, parent, roots);
    }

    @Override
    @Nonnull
    public List<INode> applyReorganization(
            @Nonnull INode node, @Nonnull INode parent, @Nonnull List<INode> roots) {
        if (performFunction == null) {
            return roots;
        }
        return performFunction.apply(node, parent, roots);
    }

    @Override
    @Nonnull
    public String asString() {
        String[] kindStrings = kind.toString().split("\\.");
        String kindName = kindStrings[kindStrings.length - 1];
        return String.format(
                "[name: %s | kind: %s | value: %s | %d subrule(s)]",
                name, kindName, value, children.size());
    }

    @Override
    @Nonnull
    public Class<? extends INode> getNodeKind() {
        return kind;
    }
}
