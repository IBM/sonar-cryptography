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
import java.util.Objects;
import javax.annotation.Nonnull;

public class ProbabilisticSignatureScheme extends Property {

    public ProbabilisticSignatureScheme(@Nonnull DetectionLocation detectionLocation) {
        super(ProbabilisticSignatureScheme.class, detectionLocation);
    }

    public ProbabilisticSignatureScheme(@Nonnull MaskGenerationFunction maskGenerationFunction) {
        super(ProbabilisticSignatureScheme.class, maskGenerationFunction.detectionLocation);
        this.append(maskGenerationFunction);
    }

    private ProbabilisticSignatureScheme(
            @Nonnull ProbabilisticSignatureScheme probabilisticSignatureScheme) {
        super(
                ProbabilisticSignatureScheme.class,
                probabilisticSignatureScheme.detectionLocation,
                probabilisticSignatureScheme.children);
    }

    @Override
    public void apply(@Nonnull Configuration configuration) {
        // nothing
    }

    @Nonnull
    @Override
    public String asString() {
        return "PSS";
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        ProbabilisticSignatureScheme copy = new ProbabilisticSignatureScheme(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof ProbabilisticSignatureScheme)) return false;
        return super.equals(object);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), "PSS");
    }
}
