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
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.utils.DetectionStoreLogger;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.Utils;
import com.ibm.plugin.rules.JavaInventoryRule;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.sonar.api.utils.log.LogTester;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.LoggerLevel;
import org.sonar.api.utils.log.Loggers;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

public abstract class TestBase extends JavaInventoryRule {
    protected final LogTester logTester = new LogTester();
    private static final Logger LOGGER = Loggers.get(TestBase.class);

    @Nonnull
    private final DetectionStoreLogger<JavaCheck, Tree, Symbol, JavaFileScannerContext>
            detectionStoreLogger = new DetectionStoreLogger<>();

    private int findingId = 0;

    public TestBase(@NotNull List<IDetectionRule<Tree>> detectionRules) {
        super(detectionRules);
    }

    public TestBase() {
        super();
    }

    @BeforeEach
    public void resetState() {
        JavaAggregator.reset();
    }

    @BeforeEach
    public void debug() {
        logTester.setLevel(LoggerLevel.DEBUG);
    }

    @Override
    public void update(@Nonnull Finding<JavaCheck, Tree, Symbol, JavaFileScannerContext> finding) {
        _update(finding, this::testFinding);
    }

    private void testFinding(
            @Nonnull
                    DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>
                            detectionStore) {
        detectionStoreLogger.print(detectionStore);

        final List<INode> nodes = javaTranslationProcess.initiate(detectionStore);
        Utils.printNodeTree(nodes);
        asserts(findingId, detectionStore, nodes);
        findingId++;
    }

    public abstract void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes);

    @Nullable public DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> getStoreWithValue(
            @Nonnull
                    List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>>
                            detectionStores) {
        return detectionStores.stream()
                .filter(store -> !store.getDetectionValues().isEmpty())
                .findFirst()
                .orElse(null);
    }

    @Nullable public DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> getStoreOfValueType(
            @Nonnull final Class<? extends IValue> valueType,
            @Nonnull
                    List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>>
                            detectionStores) {
        // Filter the relevant detection store from a list of detection stores.
        Optional<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> relevantStore =
                detectionStores.stream()
                        .filter(
                                store ->
                                        store.getDetectionValues().stream()
                                                .anyMatch(
                                                        value ->
                                                                value.getClass().equals(valueType)))
                        .findFirst();
        // Returns the store with the closest matching value type to the given valueType.
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

    @Nullable public List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>>
            getStoresOfValueType(
                    @Nonnull final Class<? extends IValue> valueType,
                    @Nonnull
                            List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>>
                                    detectionStores) {
        // Filter the relevant detection store from a list of detection stores.
        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> relevantStores =
                detectionStores.stream()
                        .filter(
                                store ->
                                        store.getDetectionValues().stream()
                                                .anyMatch(
                                                        value ->
                                                                value.getClass().equals(valueType)))
                        .toList();
        // Returns the store with the closest matching value type to the given valueType.
        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> children =
                detectionStores.stream()
                        .map(store -> getStoresOfValueType(valueType, store.getChildren()))
                        .filter(Objects::nonNull)
                        .flatMap(List::stream)
                        .toList();
        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> res =
                new ArrayList<>(relevantStores);
        res.addAll(children);
        return res;
    }
}
