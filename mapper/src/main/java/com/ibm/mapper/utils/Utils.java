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
package com.ibm.mapper.utils;

import com.ibm.mapper.model.INode;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

public final class Utils {
    private static final Logger LOGGER = Loggers.get(Utils.class);

    private Utils() {
        // singleton
    }

    public static void printNodeTree(@Nonnull List<INode> rootNodes) {
        printNodes(0, rootNodes);
    }

    private static void printNodes(int tabs, @Nonnull Collection<INode> nodes) {
        nodes.forEach(
                node -> {
                    LOGGER.debug(
                            "[translation] "
                                    + "   ".repeat(Math.max(0, tabs))
                                    + (tabs > 0 ? "└─ " : "")
                                    + "("
                                    + node.getKind().getSimpleName()
                                    + ") "
                                    + node.asString());
                    if (node.hasChildren()) {
                        printNodes(tabs + 1, node.getChildren().values());
                    }
                });
    }

    @Nonnull
    public static String addChar(@Nonnull String str, char ch, int position) {
        return str.substring(0, position) + ch + str.substring(position);
    }

    @Nonnull
    public static Optional<Integer> extractNumberFormString(@Nullable final String str) {
        if (str == null || str.isEmpty()) {
            return Optional.empty();
        }
        StringBuilder sb = new StringBuilder();
        for (char c : str.toCharArray()) {
            if (Character.isDigit(c)) {
                sb.append(c);
            }
        }

        if (sb.isEmpty()) {
            return Optional.empty();
        }

        try {
            int i = Integer.parseInt(sb.toString());
            return Optional.of(i);
        } catch (NumberFormatException ignored) {
            // ignore
        }

        return Optional.empty();
    }
}
