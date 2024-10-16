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
package com.ibm.mapper.reorganizer.rules;

import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.protocol.TLS;
import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.mapper.reorganizer.builder.ReorganizerRuleBuilder;
import java.util.ArrayList;
import java.util.Collections;
import javax.annotation.Nonnull;

public final class CipherSuiteReorganizer {

    private CipherSuiteReorganizer() {
        // nothing
    }

    @Nonnull
    public static final IReorganizerRule ADD_TLS_PROTOCOL_AS_PARENT_NODE =
            new ReorganizerRuleBuilder()
                    .createReorganizerRule()
                    .forNodeKind(CipherSuite.class)
                    .withDetectionCondition((node, parent, roots) -> parent == null)
                    .perform(
                            (node, parent, roots) -> {
                                if (node instanceof CipherSuite cipherSuite) {
                                    final TLS tls = new TLS(cipherSuite.getDetectionContext());
                                    tls.put(cipherSuite);
                                    return new ArrayList<>(Collections.singleton(tls));
                                }
                                return roots;
                            });
}
