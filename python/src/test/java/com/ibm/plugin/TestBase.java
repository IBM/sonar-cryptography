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
package com.ibm.plugin;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.model.IValue;
import com.ibm.engine.utils.DetectionStoreLogger;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.Utils;
import com.ibm.plugin.rules.PythonInventoryRule;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.BeforeEach;
import org.sonar.api.utils.log.LogTester;
import org.sonar.api.utils.log.LoggerLevel;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;

public abstract class TestBase extends PythonInventoryRule {
    protected final LogTester logTester = new LogTester();

    @Nonnull
    private final DetectionStoreLogger<PythonCheck, Tree, Symbol, PythonVisitorContext>
            detectionStoreLogger = new DetectionStoreLogger<>();

    private int findingId = 0;

    @BeforeEach
    public void debug() {
        logTester.setLevel(LoggerLevel.DEBUG);
    }

    @Override
    public void update(@Nonnull Finding<PythonCheck, Tree, Symbol, PythonVisitorContext> finding) {
        _update(finding, this::testFinding);
    }

    private void testFinding(
            @Nonnull
                    DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>
                            detectionStore) {
        detectionStoreLogger.print(detectionStore);

        List<INode> nodes = pythonTranslator.translate(detectionStore);
        Utils.printNodeTree(nodes);

        asserts(findingId, detectionStore, nodes);
        findingId++;
    }

    public abstract void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes);

    @Nullable public DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> getStoreWithValue(
            // TODO: this function (and its Java equivalent) never seem to be used
            @Nonnull
                    List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>>
                            detectionStores) {
        return detectionStores.stream()
                .filter(store -> !store.getDetectionValues().isEmpty())
                .findFirst()
                .orElse(null);
    }

    @Nullable public DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> getStoreOfValueType(
            @Nonnull final Class<? extends IValue> valueType,
            @Nonnull
                    List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>>
                            detectionStores) {
        Optional<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>> relevantStore =
                detectionStores.stream()
                        .filter(
                                store ->
                                        store.getDetectionValues().stream()
                                                .anyMatch(
                                                        value ->
                                                                value.getClass().equals(valueType)))
                        .findFirst();
        return relevantStore.orElseGet(
                () ->
                        detectionStores.stream()
                                .map(
                                        store ->
                                                Optional.ofNullable(
                                                        getStoreOfValueType(
                                                                valueType, store.getChildren())))
                                .filter(Optional::isPresent)
                                .map(Optional::get)
                                .findFirst()
                                .orElse(null));
    }

    @Nullable public List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>>
            getStoresOfValueType(
                    @Nonnull final Class<? extends IValue> valueType,
                    @Nonnull
                            List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>>
                                    detectionStores) {
        List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>> relevantStores =
                detectionStores.stream()
                        .filter(
                                store ->
                                        store.getDetectionValues().stream()
                                                .anyMatch(
                                                        value ->
                                                                value.getClass().equals(valueType)))
                        .toList();

        return relevantStores;
    }
}
