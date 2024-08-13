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
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import javax.annotation.Nonnull;

public final class PBKDF2 extends Algorithm implements PasswordBasedKeyDerivationFunction {

    public PBKDF2(@Nonnull Mac mac) {
        super("PBKDF2", PasswordBasedKeyDerivationFunction.class, mac.getDetectionContext());
        this.append(mac);
    }
}
