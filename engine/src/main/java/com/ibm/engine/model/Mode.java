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
package com.ibm.engine.model;

import javax.annotation.Nonnull;

public class Mode<T> extends AbstractValue<T> {

    @Nonnull private final String value;
    @Nonnull private final T location;

    public Mode(@Nonnull String value, @Nonnull T location) {
        this.location = location;
        this.value = value;
    }

    @Nonnull
    public String getValue() {
        return value;
    }

    @Override
    public @Nonnull T getLocation() {
        return this.location;
    }

    @Override
    public @Nonnull String asString() {
        return this.value;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Mode<?> mode)) return false;

        return value.equals(mode.value) && location.equals(mode.location);
    }

    @Override
    public int hashCode() {
        int result = value.hashCode();
        result = 31 * result + location.hashCode();
        return result;
    }
}
