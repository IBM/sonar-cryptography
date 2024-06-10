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

import com.ibm.plugin.rules.detection.PythonBaseDetectionRule;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.sonar.api.utils.log.LogTester;
import org.sonar.api.utils.log.LoggerLevel;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class ResolveValuesWithHooksTest extends PythonBaseDetectionRule {
    // This Test class structure allows to test a single class of rules instead of all rules defined
    // in PythonDetectionRules.
    // To do so, add `extends PythonBaseDetectionRule` and define a constructor using the rules you
    // want.
    // To use several rules, create a `rules()` method to call in the constructor.

    protected final LogTester logTester = new LogTester();

    protected ResolveValuesWithHooksTest() {
        super(ResolveValuesWithHooks.rules());
    }

    @BeforeEach
    public void debug() {
        logTester.setLevel(LoggerLevel.DEBUG);
    }

    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/resolve/ResolveValuesWithHooksTestFile.py", this);
    }
}
