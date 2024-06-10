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

import com.ibm.engine.detection.IBaseMethodVisitor;
import com.ibm.engine.detection.IDetectionEngine;
import com.ibm.engine.detection.TraceSymbol;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.*;

public class PythonBaseMethodVisitor extends BaseTreeVisitor implements IBaseMethodVisitor<Tree> {

    @Nonnull private final TraceSymbol<Symbol> traceSymbol;
    @Nonnull private final IDetectionEngine<Tree, Symbol> detectionEngine;

    public PythonBaseMethodVisitor(
            @Nonnull TraceSymbol<Symbol> traceSymbol,
            @Nonnull IDetectionEngine<Tree, Symbol> detectionEngine) {
        this.traceSymbol = traceSymbol;
        this.detectionEngine = detectionEngine;
    }

    @Override
    public void visitMethodDefinition(Tree method) {
        if (method instanceof FunctionDef || method instanceof FileInput) {
            method.accept(this);
        }
    }

    @Override
    public void visitCallExpression(@Nonnull CallExpression callExpression) {
        detectionEngine.run(traceSymbol, callExpression);
        super.visitCallExpression(callExpression);
    }
}
