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
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import com.ibm.output.cyclondx.CBOMOutputFile;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.annotation.Nonnull;
import org.cyclonedx.Version;
import org.cyclonedx.exception.GeneratorException;
import org.cyclonedx.generators.BomGeneratorFactory;
import org.cyclonedx.generators.json.BomJsonGenerator;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Evidence;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class TestBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(TestBase.class);

    protected final String filePath = "test.java";
    protected final int lineNumber = 1;
    protected final int offset = 1;
    protected final IBundle bundle = () -> "Test";
    protected final DetectionLocation detectionLocation =
            new DetectionLocation(filePath, lineNumber, offset, Collections.emptyList(), bundle);

    public void asserts(@Nonnull Supplier<INode> nodeSupplier, @Nonnull Consumer<Bom> assertThat) {
        final List<INode> nodes = List.of(nodeSupplier.get());
        Utils.printNodeTree("tree", nodes);

        final CBOMOutputFile outputFile = new CBOMOutputFile();
        outputFile.add(nodes);
        final Bom bom = outputFile.getBom();
        this.printBom(bom);

        assertThat.accept(bom);
    }

    protected void asserts(@Nonnull Evidence evidence) {
        assertThat(evidence.getOccurrences()).hasSize(1);
        final Occurrence occurrence = evidence.getOccurrences().get(0);
        assertThat(occurrence.getLocation()).isEqualTo(filePath);
        assertThat(occurrence.getLine()).isEqualTo(lineNumber);
        assertThat(occurrence.getOffset()).isEqualTo(offset);
        assertThat(occurrence.getAdditionalContext()).isNull();
    }

    private void printBom(@Nonnull Bom bom) {
        final BomJsonGenerator bomGenerator =
                BomGeneratorFactory.createJson(Version.VERSION_16, bom);
        try {
            final String bomString = bomGenerator.toJsonString();
            LOGGER.info(bomString);
        } catch (GeneratorException e) {
            LOGGER.error(e.getMessage());
        }
    }
}
