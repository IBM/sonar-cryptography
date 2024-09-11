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
package com.ibm.mapper.mapper.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.Test;

public class Issue127Test {

    @Test
    public void test() {
        final RSA rsa =
                new RSA(2048, new DetectionLocation("test.java", 1, 1, List.of(), () -> "Test"));
        final INode rsaCopy = rsa.deepCopy();
        assertThat(rsaCopy).isInstanceOf(RSA.class);
    }
}
