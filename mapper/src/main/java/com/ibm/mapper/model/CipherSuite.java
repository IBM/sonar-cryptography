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
import com.ibm.mapper.mapper.ssl.CipherSuiteMapper;
import com.ibm.mapper.mapper.ssl.json.JsonCipherSuite;
import com.ibm.mapper.model.collections.AlgorithmCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.jetbrains.annotations.NotNull;

public class CipherSuite implements IAsset {
    @Nonnull protected final Map<Class<? extends INode>, INode> children;
    @Nonnull protected final DetectionLocation detectionLocation;
    @Nonnull protected final Class<? extends IAsset> kind;
    @Nonnull protected String name;

    public CipherSuite(@Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        this.name = name;
        this.children = new HashMap<>();
        this.detectionLocation = detectionLocation;
        this.kind = CipherSuite.class;
    }

    public CipherSuite(
            @Nonnull String name,
            @Nullable AlgorithmCollection algorithmCollection,
            @Nullable IdentifierCollection identifierCollection,
            @Nonnull DetectionLocation detectionLocation) {
        this.name = applyStandardNaming(name);
        this.children = new HashMap<>();
        if (algorithmCollection != null) {
            this.append(algorithmCollection);
        }
        if (identifierCollection != null) {
            this.append(identifierCollection);
        }
        this.detectionLocation = detectionLocation;
        this.kind = CipherSuite.class;
    }

    public CipherSuite(
            @Nonnull String name,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull Map<Class<? extends INode>, INode> children) {
        this.name = applyStandardNaming(name);
        this.children = children;
        this.detectionLocation = detectionLocation;
        this.kind = CipherSuite.class;
    }

    private CipherSuite(@Nonnull CipherSuite cipherSuite) {
        this.children = new HashMap<>();
        this.detectionLocation = cipherSuite.detectionLocation;
        this.name = applyStandardNaming(cipherSuite.name);
        this.kind = cipherSuite.kind;
    }

    @Nonnull
    public Optional<AlgorithmCollection> getAlgorithmCollection() {
        INode node = this.getChildren().get(AlgorithmCollection.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((AlgorithmCollection) node);
    }

    @Nonnull
    public Optional<IdentifierCollection> getIdentifierCollection() {
        INode node = this.getChildren().get(IdentifierCollection.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((IdentifierCollection) node);
    }

    @Nonnull
    public String getName() {
        return name;
    }

    @Override
    @Nonnull
    public Class<? extends IAsset> getKind() {
        return kind;
    }

    @Override
    public void apply(@Nonnull Configuration configuration) {
        this.name = configuration.changeStringValue(this.name);
    }

    @Nonnull
    @Override
    public String asString() {
        return name;
    }

    @Nonnull
    @Override
    public DetectionLocation getDetectionContext() {
        return detectionLocation;
    }

    @NotNull @Override
    public String applyStandardNaming(@NotNull String name) {
        return CipherSuiteMapper.findCipherSuite(name)
                .map(JsonCipherSuite::getIanaName)
                .orElse(name);
    }

    @Nonnull
    @Override
    public Optional<INode> hasChildOfType(@Nonnull Class<? extends INode> nodeType) {
        return Optional.ofNullable(children.get(nodeType));
    }

    @Override
    public void removeChildOfType(@NotNull Class<? extends INode> nodeType) {
        this.children.remove(nodeType);
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        CipherSuite copy = new CipherSuite(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    public boolean is(@Nonnull final Class<? extends INode> type) {
        return this.getKind().equals(type);
    }

    @Override
    public void append(@Nonnull INode child) {
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
    public String toString() {
        return name;
    }
}
