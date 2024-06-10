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

import com.ibm.engine.model.IAction;
import com.ibm.engine.model.factory.IActionFactory;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public record MethodDetection<T>(@Nonnull T expression, @Nullable T markerTree)
        implements IMethodDetection<T> {

    @Nonnull
    @Override
    public Optional<IAction<T>> toValue(@Nonnull IActionFactory<T> actionFactory) {
        return actionFactory.apply(Objects.requireNonNullElse(markerTree, expression));
    }
}
