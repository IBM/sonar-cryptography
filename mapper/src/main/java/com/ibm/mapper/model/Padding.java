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

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import java.util.Map;
import java.util.Objects;

public class Padding extends Property {
    @Nonnull private String name;

    Padding(
            @Nonnull Padding padding,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull final Class<? extends Padding> asKind) {
        super(asKind, detectionLocation, padding.getChildren());
        this.name = padding.getName();
    }

    public Padding(
            @Nonnull String name,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull Map<Class<? extends INode>, INode> children) {
        super(Padding.class, detectionLocation, children);
        this.name = name;
    }

    public Padding(@Nonnull Padding padding) {
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

    @Override
    public void apply(@Nonnull Configuration configuration) {
        this.name = configuration.changeStringValue(name);
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
