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
package com.ibm.output.util;

import com.ibm.mapper.model.INode;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public final class Utils {

    private Utils() {
        // nothing
    }

    @Nullable public static INode oneOf(@Nullable INode... nodes) {
        if (nodes == null) {
            return null;
        }
        return Arrays.stream(nodes).filter(Objects::nonNull).findFirst().orElse(null);
    }

    @Nullable public static INode[] allExisting(@Nullable INode... nodes) {
        if (nodes == null) {
            return null;
        }
        return Arrays.stream(nodes).filter(Objects::nonNull).toArray(INode[]::new);
    }

    public static void pushNodesDownToFirstMatch(
            @Nonnull INode root,
            @Nonnull List<Class<? extends INode>> pushToNodeOfFirstMatchClazz,
            @Nonnull List<Class<? extends INode>> kindsOfNodesToPushDown) {
        Utils.pushNodesDownToFirstMatch(
                root, pushToNodeOfFirstMatchClazz, kindsOfNodesToPushDown, true);
    }

    public static void pushNodesDownToFirstMatch(
            @Nonnull INode root,
            @Nonnull List<Class<? extends INode>> pushToNodeOfFirstMatchClazz,
            @Nonnull List<Class<? extends INode>> kindsOfNodesToPushDown,
            boolean remove) {
        for (Class<? extends INode> kind : pushToNodeOfFirstMatchClazz) {
            if (root.hasChildOfType(kind).isPresent()) {
                pushNodesDown(root, kind, kindsOfNodesToPushDown, remove);
                return;
            }
        }
    }

    public static void pushNodesDown(
            @Nonnull INode root,
            @Nonnull Class<? extends INode> pushToNodeOfClazz,
            @Nonnull List<Class<? extends INode>> kindsOfNodesToPushDown,
            boolean remove) {
        final Optional<INode> possiblePushToNode = root.hasChildOfType(pushToNodeOfClazz);
        if (possiblePushToNode.isEmpty()) {
            return;
        }

        final INode pushToNode = possiblePushToNode.get();
        for (Class<? extends INode> kind : kindsOfNodesToPushDown) {
            root.hasChildOfType(kind)
                    .ifPresent(
                            n -> {
                                pushToNode.put(n);
                                if (remove) {
                                    root.removeChildOfType(kind);
                                }
                            });
        }
    }
}
