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
package com.ibm.engine.model.factory;

import com.ibm.engine.detection.ResolvedValue;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ParameterIdentifier;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;

public class ParameterIdentifierFactory<T> implements IValueFactory<T> {
    @Nonnull
    @Override
    public Optional<IValue<T>> apply(@NotNull ResolvedValue<Object, T> objectTResolvedValue) {
        if (objectTResolvedValue.value() instanceof String str) {
            return Optional.of(new ParameterIdentifier<>(str, objectTResolvedValue.tree()));
        } else if (objectTResolvedValue.value() instanceof Integer number) {
            return Optional.of(new ParameterIdentifier<>(number, objectTResolvedValue.tree()));
        }
        return Optional.empty();
    }
}
