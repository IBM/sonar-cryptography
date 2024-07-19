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
package com.ibm.plugin.translation;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.enricher.Enricher;
import com.ibm.mapper.ITranslationProcess;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.Reorganizer;
import com.ibm.mapper.utils.Utils;
import com.ibm.plugin.translation.translator.JavaTranslator;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.List;

public final class JavaTranslationProcess
        extends ITranslationProcess<JavaCheck, Tree, Symbol, JavaFileScannerContext> {

    public JavaTranslationProcess(
            @Nonnull JavaCheck rule, @Nonnull List<IReorganizerRule> reorganizerRules) {
        super(rule, reorganizerRules);
    }

    @Override
    @Nonnull
    public @Unmodifiable List<INode> initiate(
            @Nonnull
                    DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>
                            rootDetectionStore) {
        // 1. Translate
        JavaTranslator javaTranslator = new JavaTranslator(rule);
        List<INode> translatedValues = javaTranslator.translate(rootDetectionStore);
        Utils.printNodeTree("translated", translatedValues);

        // 2. Reorganize
        Reorganizer javaReorganizer = new Reorganizer(reorganizerRules);
        List<INode> reorganizedValues = javaReorganizer.reorganize(translatedValues);
        Utils.printNodeTree("reorganised", reorganizedValues);

        // 3. Enrich
        Enricher.enrich(reorganizedValues);
        Utils.printNodeTree("enriched", reorganizedValues);

        return Collections.unmodifiableList(reorganizedValues);
    }
}
