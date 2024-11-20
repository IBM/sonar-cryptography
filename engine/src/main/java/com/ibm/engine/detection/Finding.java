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

import com.ibm.engine.model.IValue;
import com.ibm.engine.rule.IBundle;
import java.util.List;
import javax.annotation.Nonnull;

public record Finding<R, T, S, P>(@Nonnull DetectionStore<R, T, S, P> detectionStore) {

    public int level() {
        return detectionStore.getLevel();
    }

    @Nonnull
    public IBundle bundle() {
        return detectionStore.getDetectionRule().bundle();
    }

    @Nonnull
    public T getMarkerTree() {
        return detectionStore.getDetectionValues().stream()
                .map(IValue::getLocation)
                .findFirst()
                .orElseThrow();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Finding<?, ?, ?, ?> finding)) return false;

        return this.hashCode() == finding.hashCode();
    }

    @Override
    public int hashCode() {
        return 31 * detectionStore.hashCode()
                + calculateHashCodeForChildren(detectionStore.getChildren());
    }

    private int calculateHashCodeForChildren(@Nonnull List<DetectionStore<R, T, S, P>> children) {
        return children.stream()
                .map(
                        store ->
                                31 * store.hashCode()
                                        + calculateHashCodeForChildren(store.getChildren()))
                .mapToInt(Integer::intValue)
                .sum();
    }
}
