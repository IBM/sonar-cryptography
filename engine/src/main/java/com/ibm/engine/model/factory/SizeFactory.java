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
import com.ibm.engine.model.Size;
import com.ibm.engine.utils.Utils;
import java.util.Optional;
import java.util.function.BiFunction;
import javax.annotation.Nonnull;

public abstract class SizeFactory<T> {
    @Nonnull private final Size.UnitType interpretAsUnitType;

    protected SizeFactory() {
        this.interpretAsUnitType = Size.UnitType.BYTE;
    }

    protected SizeFactory(@Nonnull Size.UnitType interpretAsUnitType) {
        this.interpretAsUnitType = interpretAsUnitType;
    }

    @Nonnull
    protected Optional<IValue<T>> apply(
            @Nonnull ResolvedValue<Object, T> objectTResolvedValue,
            @Nonnull BiFunction<Integer, T, IValue<T>> createSize) {
        return switch (this.interpretAsUnitType) {
            case BYTE ->
                    Utils.byteSizeValueToBitSizeInteger(objectTResolvedValue)
                            .map(value -> createSize.apply(value, objectTResolvedValue.tree()));
            case BIT ->
                    Utils.bitSizeValueToBitSizeInteger(objectTResolvedValue)
                            .map(value -> createSize.apply(value, objectTResolvedValue.tree()));
            case PRIME_P ->
                    Utils.bigIntegerValueToBitSizeInteger(objectTResolvedValue)
                            .map(value -> createSize.apply(value, objectTResolvedValue.tree()));
        };
    }

    //     private Size<T> createSize(int value, T tree) {
    //         return new Size<>(value, Size.UnitType.BIT, tree);
    //     }
}
