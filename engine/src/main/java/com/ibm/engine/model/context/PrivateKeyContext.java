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
package com.ibm.engine.model.context;

import java.util.Map;
import javax.annotation.Nonnull;

public class PrivateKeyContext extends KeyContext implements IDetectionContext {
    /**
     * use a property map instead
     *
     * @deprecated
     */
    @Deprecated(since = "1.3.0")
    public PrivateKeyContext(@Nonnull Kind kind) {
        super(kind);
    }

    public PrivateKeyContext(@Nonnull Map<String, String> properties) {
        super(properties);
    }

    @Nonnull
    @Override
    public Class<? extends IDetectionContext> type() {
        return PrivateKeyContext.class;
    }
}
