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
package com.ibm.mapper.model.collections;

import com.ibm.mapper.model.INode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;

import javax.annotation.Nonnull;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

public abstract class AbstractAssetCollection<K extends INode> implements IAssetCollection<K> {
    @Nonnull protected final Map<Class<? extends INode>, INode> children;
    @Nonnull protected final Class<? extends IAssetCollection<K>> kind;
    @Nonnull protected final List<K> collection;

    protected AbstractAssetCollection(
            @Nonnull List<K> collection, @Nonnull Class<? extends IAssetCollection<K>> kind) {
        this.collection = collection;
        this.children = new HashMap<>();
        this.kind = kind;
    }

    @NotNull @Unmodifiable
    @Override
    public List<K> getCollection() {
        return Collections.unmodifiableList(collection);
    }

    @Override
    public void put(@NotNull INode child) {
        this.children.put(child.getKind(), child);
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
        return this.getKind().equals(type);
    }

    @NotNull @Override
    public Class<? extends INode> getKind() {
        return this.kind;
    }

    @NotNull @Override
    public String asString() {
        final StringBuilder sb = new StringBuilder();
        for (K c : collection) {
            sb.append(c.asString()).append(", ");
        }
        return sb.toString();
    }

    @NotNull @Override
    public Optional<INode> hasChildOfType(@NotNull Class<? extends INode> nodeType) {
        return Optional.ofNullable(children.get(nodeType));
    }

    @Override
    public void removeChildOfType(@NotNull Class<? extends INode> nodeType) {
        this.children.remove(nodeType);
    }
}
