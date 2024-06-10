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
package com.ibm.engine.utils;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.*;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.apache.commons.lang3.StringUtils;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

public class DetectionStoreLogger<R, T, S, P> {
    private static final Logger LOGGER = Loggers.get(DetectionStoreLogger.class);

    public void print(@Nonnull DetectionStore<R, T, S, P> rootDetectionStore) {
        printDstoreValues(0, List.of(rootDetectionStore));
    }

    private int truncateSizeForLongNumbers = 6;

    private void printDstoreValues(
            int tabs, @Nonnull List<DetectionStore<R, T, S, P>> detectionStores) {
        detectionStores.forEach(
                store -> {
                    store.getActionValue()
                            .ifPresent(
                                    value ->
                                            LOGGER.debug(
                                                    "[id: "
                                                            + store.getStoreId()
                                                                    .toString()
                                                                    .substring(0, 5)
                                                            + ", bundle: "
                                                            + getFormattedNumericString(
                                                                    store.getDetectionRule()
                                                                            .bundle()
                                                                            .getIdentifier()
                                                                            .hashCode(),
                                                                    true,
                                                                    truncateSizeForLongNumbers)
                                                            + ", level: "
                                                            + store.getLevel()
                                                            + ", hash: "
                                                            + getFormattedNumericString(
                                                                    store.hashCode(),
                                                                    true,
                                                                    truncateSizeForLongNumbers)
                                                            + "] "
                                                            + "   ".repeat(Math.max(0, tabs))
                                                            + (tabs > 0 ? "└─ " : "")
                                                            + "("
                                                            + getDetectionValueContextMessage(
                                                                    store
                                                                            .getDetectionValueContext())
                                                            + ", "
                                                            + value.getClass().getSimpleName()
                                                            + valueSpecificString(value)
                                                            + ") "
                                                            + value.asString()));

                    final Set<Integer> visitedChildren = new HashSet<>();
                    store.detectionValuesForEachParameter(
                            (i, values) -> {
                                values.forEach(
                                        value ->
                                                LOGGER.debug(
                                                        "[id: "
                                                                + store.getStoreId()
                                                                        .toString()
                                                                        .substring(0, 5)
                                                                + ", bundle: "
                                                                + getFormattedNumericString(
                                                                        store.getDetectionRule()
                                                                                .bundle()
                                                                                .getIdentifier()
                                                                                .hashCode(),
                                                                        true,
                                                                        truncateSizeForLongNumbers)
                                                                + ", level: "
                                                                + store.getLevel()
                                                                + ", hash: "
                                                                + getFormattedNumericString(
                                                                        store.hashCode(),
                                                                        true,
                                                                        truncateSizeForLongNumbers)
                                                                + "] "
                                                                + "   ".repeat(Math.max(0, tabs))
                                                                + (tabs > 0 ? "└─ " : "")
                                                                + "("
                                                                + getDetectionValueContextMessage(
                                                                        store
                                                                                .getDetectionValueContext())
                                                                + ", "
                                                                + value.getClass().getSimpleName()
                                                                + valueSpecificString(value)
                                                                + ") "
                                                                + value.asString()));
                                store.getChildrenForParameterWithId(i)
                                        .ifPresent(
                                                children -> {
                                                    visitedChildren.add(i);
                                                    printDstoreValues(tabs + 1, children);
                                                });
                            });

                    printDstoreValues(tabs + 1, store.getChildrenForMethod());
                    store.childrenForEachParameter(
                            (i, childStore) -> {
                                if (!visitedChildren.contains(i)) {
                                    printDstoreValues(tabs + 1, childStore);
                                }
                            });
                });
    }

    @Nonnull
    private String valueSpecificString(@Nonnull IValue<T> value) {
        if (value instanceof Size<T> keySize) {
            return "<" + keySize.getUnitType().name().toLowerCase() + ">";
        } else if (value instanceof AlgorithmParameter<T> algorithmParameter) {
            return "<" + algorithmParameter.getKind() + ">";
        }
        return "";
    }

    @Nonnull
    private String getDetectionValueContextMessage(
            @Nonnull IDetectionContext detectionValueContext) {
        if (detectionValueContext instanceof ISupportKind<?>) {
            return detectionValueContext.getClass().getSimpleName()
                    + "<"
                    + ((ISupportKind<?>) detectionValueContext).kind()
                    + ">";
        } else {
            return detectionValueContext.getClass().getSimpleName();
        }
    }

    @Nonnull
    String getFormattedNumericString(
            int hashInt, boolean canBeNegative, @Nullable Integer maxCharacters) {
        String res = "";
        if (canBeNegative && hashInt >= 0) {
            res += "";
        }
        res += Integer.toString(hashInt);

        if (maxCharacters != null) {
            if (maxCharacters < 3) {
                throw new IllegalArgumentException(
                        "Max characters must be greater than or equal to 3");
            } else if (res.length() > maxCharacters) {
                res = res.substring(0, maxCharacters - 1) + "…";
            } else if (res.length() < maxCharacters) {
                res += StringUtils.repeat(" ", maxCharacters - res.length());
            }
        }
        if (maxCharacters != null && res.length() > maxCharacters) {
            res = res.substring(0, maxCharacters - 1) + "…";
        }
        return res;
    }
}
