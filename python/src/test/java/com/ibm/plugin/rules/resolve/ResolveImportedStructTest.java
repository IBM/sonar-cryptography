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
package com.ibm.plugin.rules.resolve;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

class ResolveImportedStructTest extends TestBase {
    // This Test class structure allows testing a single class of rules instead of all rules defined
    // in PythonDetectionRules.
    // To do so, add `extends PythonBaseDetectionRule` and define a constructor using the rules you
    // want.
    // To use several rules, create a `rules()` method to call in the constructor.

    public ResolveImportedStructTest() {
        super(ResolveImportedStruct.rules());
    }

    @Override
    public void asserts(
            int findingId,
            @NotNull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @NotNull List<INode> nodes) {
        // nothing
    }

    @Disabled("feature not supported/implemented")
    @Test
    void test() {
        PythonCheckVerifier.verify(
                List.of(
                        "src/test/files/rules/resolve/ResolveImportedStructTestFile.py",
                        "src/test/files/rules/resolve/imports/ResolveImportedStructImport.py"),
                this);
    }
}
