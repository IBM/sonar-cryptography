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
package com.ibm.engine.detection;

import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.Parameter;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nonnull;

public record MatchContext(
        boolean isHookContext,
        boolean objectShouldMatchExactTypes,
        @Nonnull List<Boolean> parametersShouldMatchExactTypes) {

    public static @Nonnull MatchContext createForHookContext() {
        return new MatchContext(true, false, List.of());
    }

    @Nonnull
    public static <T> MatchContext build(
            boolean isHookContext, @Nonnull IDetectionRule<T> iDetectionRule) {
        List<Boolean> parameters = new ArrayList<>();
        if (iDetectionRule instanceof DetectionRule<T> detectionRule) {
            parameters =
                    detectionRule.parameters().stream()
                            .map(Parameter::shouldMatchExactTypes)
                            .toList();
        }
        return new MatchContext(isHookContext, iDetectionRule.shouldMatchExactTypes(), parameters);
    }
}
