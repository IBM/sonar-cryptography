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
import com.ibm.plugin.translation.translator.PythonTranslator;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;

public final class PythonTranslationProcess
        extends ITranslationProcess<PythonCheck, Tree, Symbol, PythonVisitorContext> {

    public PythonTranslationProcess(@Nonnull List<IReorganizerRule> reorganizerRules) {
        super(reorganizerRules);
    }

    @Nonnull
    @Override
    public List<INode> initiate(
            @Nonnull
                    DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>
                            rootDetectionStore) {
        // 1. Translate
        final PythonTranslator pythonTranslator = new PythonTranslator();
        final List<INode> translatedValues = pythonTranslator.translate(rootDetectionStore);
        Utils.printNodeTree(" translated ", translatedValues);

        // 2. Reorganize
        final Reorganizer pythonReorganizer = new Reorganizer(reorganizerRules);
        final List<INode> reorganizedValues = pythonReorganizer.reorganize(translatedValues);
        Utils.printNodeTree("reorganised ", reorganizedValues);

        // 3. Enrich
        final List<INode> enrichedValues = Enricher.enrich(reorganizedValues).stream().toList();
        Utils.printNodeTree("  enriched  ", enrichedValues);

        return Collections.unmodifiableCollection(enrichedValues).stream().toList();
    }
}
