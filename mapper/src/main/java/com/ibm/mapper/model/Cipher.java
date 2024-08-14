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

import java.util.Optional;
import javax.annotation.Nonnull;

public interface Cipher extends IPrimitive {

    @Nonnull
    default Optional<Mode> getMode() {
        INode node = this.getChildren().get(Mode.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((Mode) node);
    }

    @Nonnull
    default Optional<Padding> getPadding() {
        INode node = this.getChildren().get(Padding.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((Padding) node);
    }

    @Nonnull
    default Optional<KeyLength> getKeyLength() {
        INode node = this.getChildren().get(KeyLength.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((KeyLength) node);
    }
}
