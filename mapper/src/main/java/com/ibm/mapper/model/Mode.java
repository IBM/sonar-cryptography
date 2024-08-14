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
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;

public class Mode extends Property {
    @Nonnull private final String name;

    public Mode(@Nonnull String name, @Nonnull DetectionLocation detectionLocation) {
        super(Mode.class, detectionLocation);
        this.name = name;
    }

    public Mode(
            @Nonnull String name,
            @Nonnull BlockSize blockSize,
            @Nonnull DetectionLocation detectionLocation) {
        super(Mode.class, detectionLocation);
        this.name = name;
        this.put(blockSize);
    }

    private Mode(@Nonnull Mode mode) {
        super(mode.type, mode.detectionLocation, mode.children);
        this.name = mode.name;
    }

    @Nonnull
    public String getName() {
        return name;
    }

    @Nonnull
    public Optional<BlockSize> getBlockSize() {
        INode node = this.getChildren().get(BlockSize.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((BlockSize) node);
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
        Mode copy = new Mode(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof Mode mode)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(name, mode.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), name);
    }
}
