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
package com.ibm.output.statistics;

import com.ibm.mapper.model.INode;
import java.util.Map;
import java.util.function.Consumer;
import java.util.function.IntSupplier;
import java.util.function.Supplier;
import javax.annotation.Nonnull;

public final class ScanStatistics implements IStatistics {
    private final int numberOfDetectedAssets;
    @Nonnull private final Map<Class<? extends INode>, Long> numberOfAssetsPerType;

    public ScanStatistics(
            @Nonnull IntSupplier numberOfDetectedAssetsSupplier,
            @Nonnull Supplier<Map<Class<? extends INode>, Long>> numberOfAssetsPerTypeSupplier) {
        this.numberOfDetectedAssets = numberOfDetectedAssetsSupplier.getAsInt();
        this.numberOfAssetsPerType = numberOfAssetsPerTypeSupplier.get();
    }

    @Override
    public void print(@Nonnull Consumer<String> out) {
        out.accept("========== CBOM Statistics ==========");
        out.accept(String.format("%-33s: %s", "Detected Assets", numberOfDetectedAssets));
        for (Map.Entry<Class<? extends INode>, Long> entry : numberOfAssetsPerType.entrySet()) {
            out.accept(
                    String.format(
                            " - %-30s: %s", entry.getKey().getSimpleName(), entry.getValue()));
        }
        out.accept("=====================================");
    }
}
