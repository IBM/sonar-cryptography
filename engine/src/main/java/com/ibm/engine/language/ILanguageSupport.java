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
package com.ibm.engine.language;

import com.ibm.engine.detection.*;
import com.ibm.engine.executive.DetectionExecutive;
import com.ibm.engine.rule.IDetectionRule;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public interface ILanguageSupport<R, T, S, P> {
    @Nonnull
    ILanguageTranslation<T> translation();

    @Nonnull
    DetectionExecutive<R, T, S, P> createDetectionExecutive(
            @Nonnull T tree,
            @Nonnull IDetectionRule<T> detectionRule,
            @Nonnull IScanContext<R, T> scanContext);

    @Nonnull
    IDetectionEngine<T, S> createDetectionEngineInstance(
            @Nonnull DetectionStore<R, T, S, P> detectionStore);

    @Nonnull
    IScanContext<R, T> createScanContext(@Nonnull P publisher);

    @Nonnull
    IBaseMethodVisitorFactory<T, S> getBaseMethodVisitorFactory();

    @Nonnull
    Optional<T> getEnclosingMethod(@Nonnull T expression);

    @Nullable MethodMatcher<T> createMethodMatcherBasedOn(@Nonnull T methodDefinition);

    @Nullable EnumMatcher<T> createSimpleEnumMatcherFor(
            @Nonnull T enumIdentifier, @Nonnull MatchContext matchContext);
}
