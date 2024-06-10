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
package com.ibm.engine.language.python;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.detection.*;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.language.ILanguageSupport;
import com.ibm.engine.language.ILanguageTranslation;
import com.ibm.engine.language.IScanContext;
import com.ibm.engine.rule.IDetectionRule;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.*;

public class PythonLanguageSupport
        implements ILanguageSupport<PythonCheck, Tree, Symbol, PythonVisitorContext> {
    @Nonnull private final Handler<PythonCheck, Tree, Symbol, PythonVisitorContext> handler;

    public PythonLanguageSupport() {
        this.handler = new Handler<>(this);
    }

    @Nonnull
    @Override
    public ILanguageTranslation<Tree> translation() {
        return new PythonLanguageTranslation();
    }

    @Override
    public @NotNull DetectionExecutive<PythonCheck, Tree, Symbol, PythonVisitorContext>
            createDetectionExecutive(
                    @NotNull Tree tree,
                    @NotNull IDetectionRule<Tree> detectionRule,
                    @NotNull IScanContext<PythonCheck, Tree> scanContext) {
        return new DetectionExecutive<>(tree, detectionRule, scanContext, this.handler);
    }

    @Override
    public @NotNull IDetectionEngine<Tree, Symbol> createDetectionEngineInstance(
            @NotNull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>
                            detectionStore) {
        return new PythonDetectionEngine(detectionStore, this.handler);
    }

    @Override
    public @NotNull IScanContext<PythonCheck, Tree> createScanContext(
            @NotNull PythonVisitorContext publisher) {
        return new PythonScanContext(publisher);
    }

    @Override
    public @NotNull IBaseMethodVisitorFactory<Tree, Symbol> getBaseMethodVisitorFactory() {
        return PythonBaseMethodVisitor::new;
    }

    @Override
    public @NotNull Optional<Tree> getEnclosingMethod(@NotNull Tree expression) {
        // In Python, there isn't necessarily an enclosing method: we return it if it exists,
        // otherwise we return the highest level root node corresponding to all the content of the
        // current file.
        if (expression instanceof FunctionDef functionDefTree) {
            return Optional.ofNullable(functionDefTree);
        } else if (expression instanceof FileInput fileInputTree) {
            return Optional.ofNullable(fileInputTree);
        } else if (expression.parent() != null) {
            return getEnclosingMethod(expression.parent());
        }
        return Optional.empty();
    }

    @Override
    public MethodMatcher<Tree> createMethodMatcherBasedOn(@NotNull Tree methodDefinition) {
        if (methodDefinition instanceof FunctionDef functionDefTree) {
            // The `invocationObjectName` consists of the filename + the class(es). We use
            // `fullyQualifiedName`, here that basically is `invocationObjectName` + the function
            // name, to which we remove the function name.
            String invocationObjectName;
            Optional<String> invocationObjectNameOptional =
                    Optional.ofNullable(functionDefTree)
                            .map(FunctionDef::name)
                            .map(Name::symbol)
                            .map(Symbol::fullyQualifiedName);
            invocationObjectName =
                    invocationObjectNameOptional.isPresent()
                            ? invocationObjectNameOptional.get()
                            : "";

            int lastDotIndex = invocationObjectName.lastIndexOf(".");
            lastDotIndex = lastDotIndex == -1 ? invocationObjectName.length() : lastDotIndex;
            invocationObjectName = invocationObjectName.substring(0, lastDotIndex);

            String name = functionDefTree.name().name();

            ParameterList parameterList = functionDefTree.parameters();
            LinkedList<String> parameterTypeList = new LinkedList<>();
            if (parameterList != null) {
                String[] parameters =
                        parameterList.all().stream()
                                // TODO: I don't think we can do better tham using type ANY for each
                                // parameter
                                .map(param -> ANY)
                                .toArray(String[]::new);
                parameterTypeList = new LinkedList<>(Arrays.asList(parameters));
            }

            return new MethodMatcher<>(invocationObjectName, name, parameterTypeList);
        }
        return null;
    }

    @Override
    public EnumMatcher<Tree> createSimpleEnumMatcherFor(
            @NotNull Tree enumIdentifier, @Nonnull MatchContext matchContext) {
        Optional<String> enumIdentifierName =
                translation().getEnumIdentifierName(matchContext, enumIdentifier);
        return enumIdentifierName.<EnumMatcher<Tree>>map(EnumMatcher::new).orElse(null);
    }
}
