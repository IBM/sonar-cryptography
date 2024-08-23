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

import com.ibm.mapper.ITranslator;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.collections.IAssetCollection;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class Utils {
    private static final Logger LOGGER = LoggerFactory.getLogger(Utils.class);

    private Utils() {
        // singleton
    }

    public static void printNodeTree(@Nonnull final String step, @Nonnull List<INode> rootNodes) {
        printNodes(step, 0, rootNodes);
    }

    private static void printNodes(
            @Nonnull final String step, int tabs, @Nonnull Collection<INode> nodes) {
        nodes.forEach(
                node -> {
                    LOGGER.debug(
                            "[{}] {}{}({}) {}",
                            step,
                            "   ".repeat(Math.max(0, tabs)),
                            tabs > 0 ? "└─ " : "",
                            node.getKind().getSimpleName(),
                            node.asString());
                    if (node.hasChildren()) {
                        printNodes(step, tabs + 1, node.getChildren().values());
                    }

                    if (node instanceof IAssetCollection<?>) {
                        IAssetCollection<INode> collection = (IAssetCollection<INode>) node;
                        printNodes(step, tabs + 1, collection.getCollection());
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

    public static Algorithm unknown(
            @Nonnull final Class<? extends IPrimitive> asKind,
            DetectionLocation detectionLocation) {
        return new Algorithm(ITranslator.UNKNOWN, asKind, detectionLocation);
    }

    public static Algorithm cipherWithMode(@Nonnull Algorithm cipher, @Nonnull Mode mode) {
        cipher.put(mode);
        return cipher;
    }

    public static Algorithm unknownWithMode(
            @Nonnull Mode mode, @Nonnull final Class<? extends IPrimitive> asKind) {
        Algorithm cipher = unknown(asKind, mode.getDetectionContext());
        return cipherWithMode(cipher, mode);
    }

    public static Algorithm cipherWithPadding(@Nonnull Algorithm cipher, @Nonnull Padding padding) {
        cipher.put(padding);
        return cipher;
    }

    public static Algorithm unknownWithPadding(
            @Nonnull Padding padding, @Nonnull final Class<? extends IPrimitive> asKind) {
        Algorithm cipher = unknown(asKind, padding.getDetectionContext());
        return cipherWithPadding(cipher, padding);
    }
}
