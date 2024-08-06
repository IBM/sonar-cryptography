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
package com.ibm.mapper.model;

import com.ibm.mapper.utils.DetectionLocation;
import java.util.HashMap;
import java.util.Objects;
import javax.annotation.Nonnull;

public class Padding extends Property {
    @Nonnull private final String name;

    public Padding(@Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        super(Padding.class, detectionLocation, new HashMap<>());
        this.name = name;
    }

    protected Padding(
            @Nonnull String name,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull Class<? extends Padding> kind) {
        super(kind, detectionLocation, new HashMap<>());
        this.name = name;
    }

    private Padding(@Nonnull Padding padding) {
        super(padding.type, padding.detectionLocation, padding.children);
        this.name = padding.name;
    }

    @Nonnull
    public String getName() {
        return name;
    }

    @Override
    public String toString() {
        return this.name;
    }

    @Nonnull
    @Override
    public String asString() {
        return name;
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        Padding copy = new Padding(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof Padding padding)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(name, padding.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), name);
    }
}
