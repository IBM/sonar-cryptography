/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
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
package com.ibm.plugin.rules.detection.dotnet;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.Mode;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;

/**
 * Verifies that reassigning an alias redirects later property setters to the new target.
 *
 * <pre>{@code
 * var first = Aes.Create();
 * var second = TripleDES.Create();
 * var alias = first;
 * alias = second;
 * alias.Mode = CipherMode.CBC;
 * }</pre>
 *
 * <p>Only {@code second} (TripleDES) may receive {@code Mode=CBC}; {@code first} (AES) must stay
 * without a mode.
 */
class DotNetAESAliasReassignmentTest extends TestBase {

    @Test
    void testAliasReassignment() throws Exception {
        CSharpVerifier.verify(
                "rules/detection/dotnet/ProbeCSharpAliasReassignmentTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(nodes).hasSize(1);
        String algorithm = detectionStore.getDetectionValues().get(0).asString();
        DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext> modeStore =
                getStoreOfValueType(Mode.class, detectionStore.getChildren());
        if (algorithm.equals("AES")) {
            // the stale alias must not leak Mode onto the first object
            assertThat(modeStore).isNull();
            assertThat(nodes.get(0).asString()).doesNotContain("CBC");
        } else {
            assertThat(algorithm).isEqualTo("TRIPLEDES");
            assertThat(modeStore).isNotNull();
            assertThat(modeStore.getDetectionValues().get(0).asString()).isEqualTo("CBC");
        }
    }
}
