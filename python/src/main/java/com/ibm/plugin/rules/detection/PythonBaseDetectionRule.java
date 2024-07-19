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
package com.ibm.plugin.rules.detection;

import com.ibm.common.IObserver;
import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.language.python.PythonScanContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.PythonAggregator;
import com.ibm.plugin.translation.PythonTranslationProcess;
import java.util.List;
import java.util.function.Consumer;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.VisibleForTesting;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.CallExpression;
import org.sonar.plugins.python.api.tree.Tree;

public abstract class PythonBaseDetectionRule extends PythonVisitorCheck
        implements IObserver<Finding<PythonCheck, Tree, Symbol, PythonVisitorContext>> {

    @Nonnull protected final PythonTranslationProcess pythonTranslationProcess;
    @Nonnull protected final List<IDetectionRule<Tree>> detectionRules;

    protected PythonBaseDetectionRule(
            @Nonnull List<IDetectionRule<Tree>> detectionRules,
            @Nonnull List<IReorganizerRule> reorganizerRules) {
        this.detectionRules = detectionRules;
        this.pythonTranslationProcess = new PythonTranslationProcess(this, reorganizerRules);
    }

    @Override
    public void visitCallExpression(@Nonnull CallExpression tree) {
        detectionRules.forEach(
                rule -> {
                    DetectionExecutive<PythonCheck, Tree, Symbol, PythonVisitorContext>
                            detectionExecutive =
                                    PythonAggregator.getLanguageSupport()
                                            .createDetectionExecutive(
                                                    tree,
                                                    rule,
                                                    new PythonScanContext(this.getContext()));
                    detectionExecutive.subscribe(this);
                    detectionExecutive.start();
                });
        super.visitCallExpression(tree); // Necessary to visit children nodes of this CallExpression
    }

    /**
     * Updates the output file with the translated nodes resulting from a finding.
     *
     * @param finding A finding containing detection store information.
     */
    @Override
    public void update(@Nonnull Finding<PythonCheck, Tree, Symbol, PythonVisitorContext> finding) {
        _update(finding, this::handleFinding);
    }

    @VisibleForTesting
    @SuppressWarnings("java:S100")
    protected void _update(
            @Nonnull Finding<PythonCheck, Tree, Symbol, PythonVisitorContext> finding,
            @Nonnull
                    Consumer<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>>
                            storeConsumer) {
        storeConsumer.accept(finding.detectionStore());
    }

    private void handleFinding(
            @Nonnull
                    DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>
                            detectionStore) {
        List<INode> nodes = pythonTranslationProcess.initiate(detectionStore);
        PythonAggregator.addNodes(nodes);
    }
}
