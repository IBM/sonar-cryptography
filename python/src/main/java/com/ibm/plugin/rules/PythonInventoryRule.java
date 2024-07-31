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
package com.ibm.plugin.rules;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.plugin.rules.detection.PythonBaseDetectionRule;
import com.ibm.plugin.rules.detection.PythonDetectionRules;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;
import org.jetbrains.annotations.VisibleForTesting;
import org.sonar.check.Rule;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;

@Rule(key = "Inventory")
public class PythonInventoryRule extends PythonBaseDetectionRule {

    public PythonInventoryRule() {
        super(PythonDetectionRules.rules(), List.of());
    }

    @VisibleForTesting
    protected PythonInventoryRule(@Nonnull List<IDetectionRule<Tree>> detectionRules) {
        super(detectionRules, List.of());
    }

    @Override
    public void report(
            @NotNull @Unmodifiable
                    DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @NotNull PythonCheck rule) {
        detectionStore
                .getDetectionValues()
                .forEach(
                        iValue ->
                                detectionStore
                                        .getScanContext()
                                        .reportIssue(
                                                rule, iValue.getLocation(), iValue.asString()));
    }
}
