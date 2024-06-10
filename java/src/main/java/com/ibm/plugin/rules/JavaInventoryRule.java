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

import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.rules.detection.JavaBaseDetectionRule;
import com.ibm.plugin.rules.detection.JavaDetectionRules;
import com.ibm.plugin.translation.reorganizer.JavaReorganizerRules;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.VisibleForTesting;
import org.sonar.check.Rule;
import org.sonar.plugins.java.api.tree.Tree;

@Rule(key = "Inventory")
public class JavaInventoryRule extends JavaBaseDetectionRule {
    public JavaInventoryRule() {
        super(JavaDetectionRules.rules(), JavaReorganizerRules.rules());
    }

    @VisibleForTesting
    protected JavaInventoryRule(@Nonnull List<IDetectionRule<Tree>> detectionRules) {
        super(detectionRules, JavaReorganizerRules.rules());
    }

    @VisibleForTesting
    protected JavaInventoryRule(
            @Nonnull List<IDetectionRule<Tree>> detectionRules,
            @Nonnull List<IReorganizerRule> reorganizerRules) {
        super(detectionRules, reorganizerRules);
    }
}
