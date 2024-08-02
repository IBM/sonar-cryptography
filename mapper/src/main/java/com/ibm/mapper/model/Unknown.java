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
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;

public final class Unknown implements INode {
    @Nonnull private final Map<Class<? extends INode>, INode> children;
    @Nonnull private final DetectionLocation detectionLocation;
    @Nonnull private final String name;

    public Unknown(@Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        this.name = name;
        this.children = new HashMap<>();
        this.detectionLocation = detectionLocation;
    }

    private Unknown(@Nonnull Unknown unknown) {
        this.children = new HashMap<>();
        this.detectionLocation = unknown.detectionLocation;
        this.name = unknown.name;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Unknown unknown)) return false;

        return detectionLocation.equals(unknown.detectionLocation) && name.equals(unknown.name);
    }

    @Override
    public int hashCode() {
        int result = detectionLocation.hashCode();
        result = 31 * result + name.hashCode();
        return result;
    }

    @Override
    public void append(@NotNull INode child) {
        this.children.put(child.getClass(), child);
    }

    @Override
    public boolean hasChildren() {
        return !this.children.isEmpty();
    }

    @NotNull @Override
    public Map<Class<? extends INode>, INode> getChildren() {
        return this.children;
    }

    @Override
    public boolean is(@NotNull Class<? extends INode> type) {
        return type.equals(Unknown.class);
    }

    @NotNull @Override
    public Class<? extends INode> getKind() {
        return Unknown.class;
    }

    @NotNull @Override
    public String asString() {
        return name;
    }

    @NotNull @Override
    public Optional<INode> hasChildOfType(@NotNull Class<? extends INode> nodeType) {
        return Optional.ofNullable(children.get(nodeType));
    }

    @Override
    public void removeChildOfType(@NotNull Class<? extends INode> nodeType) {
        this.children.remove(nodeType);
    }

    @NotNull @Override
    public INode deepCopy() {
        Unknown copy = new Unknown(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }
}
