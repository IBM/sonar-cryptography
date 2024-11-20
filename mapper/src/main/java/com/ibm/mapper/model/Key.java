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
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;

public class Key implements IAsset {
    @Nonnull protected final Map<Class<? extends INode>, INode> children;
    @Nonnull protected final Class<? extends Key> kind;
    @Nonnull protected final DetectionLocation detectionLocation;
    @Nonnull protected final String name;

    public Key(@Nonnull IAlgorithm algorithm) {
        this.name = algorithm.getName();
        this.children = new HashMap<>();
        this.children.put(algorithm.getKind(), algorithm);
        this.detectionLocation = algorithm.getDetectionContext();
        this.kind = Key.class;
    }

    protected Key(
            @Nonnull Key key,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull final Class<? extends Key> asKind) {
        this.name = key.name;
        this.children = key.getChildren();
        this.detectionLocation = detectionLocation;
        this.kind = asKind;
    }

    protected Key(@Nonnull IAlgorithm algorithm, @Nonnull final Class<? extends Key> asKind) {
        this.name = algorithm.getName();
        this.children = new HashMap<>();
        this.children.put(algorithm.getKind(), algorithm);
        this.detectionLocation = algorithm.getDetectionContext();
        this.kind = asKind;
    }

    private Key(@Nonnull Key key) {
        this.children = new HashMap<>();
        this.kind = key.kind;
        this.detectionLocation = key.detectionLocation;
        this.name = key.name;
    }

    @Nonnull
    public String getName() {
        return name;
    }

    @Nonnull
    @Override
    public String asString() {
        return name;
    }

    @Override
    public void put(@Nonnull INode child) {
        this.children.put(child.getKind(), child);
    }

    @Override
    public boolean hasChildren() {
        return !this.children.isEmpty();
    }

    @Nonnull
    @Override
    public Map<Class<? extends INode>, INode> getChildren() {
        return this.children;
    }

    @Override
    public boolean is(@Nonnull Class<? extends INode> type) {
        return this.kind.equals(type);
    }

    @Nonnull
    @Override
    public Class<? extends INode> getKind() {
        return this.kind;
    }

    @Nonnull
    @Override
    public DetectionLocation getDetectionContext() {
        return detectionLocation;
    }

    @Nonnull
    @Override
    public Optional<INode> hasChildOfType(@Nonnull Class<? extends INode> nodeType) {
        return Optional.ofNullable(children.get(nodeType));
    }

    @Override
    public void removeChildOfType(@Nonnull Class<? extends INode> nodeType) {
        this.children.remove(nodeType);
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        Key copy = new Key(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof Key key)) return false;
        return Objects.equals(kind, key.kind)
                && Objects.equals(detectionLocation, key.detectionLocation)
                && Objects.equals(name, key.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, detectionLocation, name);
    }
}
