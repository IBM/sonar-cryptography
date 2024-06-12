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
package com.ibm.plugin;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

public abstract class TestBaseWithAnnotations extends TestBase {

    private Map<Integer, Integer> addedLinesMap = new HashMap<>();

    @Override
    protected void testFinding(
            @Nonnull
                    DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>
                            detectionStore) {
        super.detectionStoreLogger.print(detectionStore);

        final List<INode> nodes = javaTranslationProcess.initiate(detectionStore);
        Utils.printNodeTree(nodes);
        asserts(findingId, detectionStore, nodes);
        outputFunction(nodes);
        findingId++;
    }

    /**
     * Simulates the call that would be made from the plugin to the output layer when running with
     * SonarQube.
     *
     * @param nodes - The roots of the trees of translated nodes
     */
    public void outputFunction(@Nonnull List<INode> nodes) {
        Map<String, List<INode>> organizedNodes = cleanAndOrganizeNodes(nodes);

        for (Map.Entry<String, List<INode>> entry : organizedNodes.entrySet()) {
            String filePath = entry.getKey();
            List<INode> nodeList = entry.getValue();

            for (INode node : nodeList) {
                if (node instanceof com.ibm.mapper.model.Algorithm algorithmNode) {
                    DetectionLocation detectionContext = algorithmNode.getDetectionContext();
                    Integer originalLineNumber = detectionContext.lineNumber();
                    Integer lineNumber = getUpdatedLineNumber(originalLineNumber);
                    List<String> content = getCryptographicRepresentation(nodes);

                    try {
                        List<String> fileContent =
                                new ArrayList<>(Files.readAllLines(Paths.get(filePath)));
                        // Ensure the line number is within the file's range
                        if (lineNumber > 0 && lineNumber <= fileContent.size()) {
                            // Determine the indentation level of the specified line
                            String targetLine = fileContent.get(lineNumber - 1);
                            String indentation = targetLine.replaceAll("^(\\s*).*", "$1");

                            // Add each line of the content with the same indentation
                            for (int i = 0; i < content.size(); i++) {
                                String indentedContent = indentation + content.get(i);
                                fileContent.add(
                                        lineNumber - 1 + i,
                                        indentedContent); // Adjust the index for each new line
                            }
                            Files.write(
                                    Paths.get(filePath),
                                    fileContent,
                                    StandardOpenOption.WRITE,
                                    StandardOpenOption.TRUNCATE_EXISTING);

                            // Update the map of line numbers
                            updateAddedLinesMap(originalLineNumber, content.size());
                        } else {
                            System.err.println(
                                    "Line number "
                                            + lineNumber
                                            + " is out of range for file "
                                            + filePath);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        return;
    }

    private int getUpdatedLineNumber(int lineNumber) {
        int updatedLineNumber = lineNumber;
        for (Map.Entry<Integer, Integer> entry : addedLinesMap.entrySet()) {
            Integer lineIndex = entry.getKey();
            Integer numberOfAddedLines = entry.getValue();

            if (lineIndex < lineNumber) {
                updatedLineNumber += numberOfAddedLines;
            }
        }
        return updatedLineNumber;
    }

    private void updateAddedLinesMap(int lineNumber, int numberOfAddedLines) {
        if (addedLinesMap.containsKey(lineNumber)) {
            addedLinesMap.put(lineNumber, addedLinesMap.get(lineNumber) + numberOfAddedLines);
        } else {
            addedLinesMap.put(lineNumber, numberOfAddedLines);
        }
    }

    private Map<String, List<INode>> cleanAndOrganizeNodes(@Nonnull List<INode> nodes) {
        return nodes.stream()
                .filter(node -> node instanceof com.ibm.mapper.model.Algorithm)
                .map(node -> (com.ibm.mapper.model.Algorithm) node)
                .collect(
                        Collectors.groupingBy(
                                algorithmNode -> algorithmNode.getDetectionContext().filePath(),
                                Collectors.collectingAndThen(
                                        Collectors.toList(),
                                        (List<com.ibm.mapper.model.Algorithm> list) ->
                                                list.stream()
                                                        .sorted(
                                                                Comparator.comparingInt(
                                                                        node ->
                                                                                -node.getDetectionContext()
                                                                                        .lineNumber()))
                                                        .map(node -> (INode) node)
                                                        .collect(Collectors.toList()))));
    }

    private List<String> getCryptographicRepresentation(@Nonnull List<INode> rootNodes) {
        return Stream.of(
                        List.of("/*@ CRYPTOGRAPHIC INFORMATION: @*/").stream(),
                        getCryptographicRepresentationRecursive(0, rootNodes).stream())
                .flatMap(i -> i)
                .toList();
    }

    private List<String> getCryptographicRepresentationRecursive(
            int tabs, @Nonnull Collection<INode> nodes) {
        List<String> content = new LinkedList<>();
        nodes.forEach(
                node -> {
                    content.add(
                            "/*@ "
                                    + "   ".repeat(Math.max(0, tabs))
                                    + (tabs > 0 ? "└─ " : "")
                                    + "("
                                    + node.getKind().getSimpleName()
                                    + ") "
                                    + node.asString()
                                    + " @*/");
                    if (node.hasChildren()) {
                        content.addAll(
                                getCryptographicRepresentationRecursive(
                                        tabs + 1, node.getChildren().values()));
                    }
                });
        return content;
    }
}
