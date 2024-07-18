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
package com.ibm.engine.serializer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.rule.DetectionRule;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.MethodDetectionRule;
import com.ibm.engine.rule.Parameter;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Queue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class ExportRules {
    private static final Logger LOGGER = LoggerFactory.getLogger(ExportRules.class);

    protected <T> void exportToJSON(
            List<IDetectionRule<T>> listOfEntryPoints, FileWriter fileWriter) {

        List<DetectionRuleStore<T>> nodes = createListOfDetectionRules(listOfEntryPoints);

        try {
            // Create an object mapper instance
            ObjectMapper objectMapper = new ObjectMapper();

            // Disable FAIL_ON_EMPTY_BEANS to ignore non-serializable objects
            // (rather than throwing an error)
            objectMapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);

            // Register custom MethodMatcher serializer
            SimpleModule module1 = new SimpleModule();
            module1.addSerializer(MethodMatcher.class, new MethodMatcherSerializer());
            objectMapper.registerModule(module1);

            // Register custom DetectionRuleStore serializer
            SimpleModule module2 = new SimpleModule();
            module2.addSerializer(DetectionRuleStore.class, new DetectionRuleStoreSerializer());
            objectMapper.registerModule(module2);

            // Export all rules to a JSON string
            ObjectWriter ow = objectMapper.writer().withDefaultPrettyPrinter();
            String json = ow.writeValueAsString(nodes);

            // Write JSON to a new file
            fileWriter.write(json);
            LOGGER.info("Java rules exported to 'target/rules.json' successfully.");

        } catch (Exception e) {
            LOGGER.warn("Error exporting Java rules to JSON file: " + e.getMessage());
        }
    }

    private <T> List<DetectionRuleStore<T>> createListOfDetectionRules(
            List<IDetectionRule<T>> listOfEntryPoints) {
        LOGGER.info("Loading...");

        // Map of matcher ID to detection rule
        HashMap<String, DetectionRuleStore<T>> rulesMap = new HashMap<>();
        // Queue of detection rules to visit
        Queue<IDetectionRule<T>> rulesToVisit = new LinkedList<>();

        int visited = 0;

        // Initialize with all entry point detection rules
        rulesToVisit.addAll(listOfEntryPoints);
        int n = listOfEntryPoints.size();

        while (!rulesToVisit.isEmpty()) {
            IDetectionRule<T> currentRule = rulesToVisit.remove();
            MethodMatcher<T> matcher = getMatcher(currentRule);
            if (matcher != null) {
                DetectionRuleStore<T> detectionRuleStore;
                String currentMatcherID = DetectionRuleStore.getMatcherID(matcher);

                if (rulesMap.get(currentMatcherID) == null) {
                    // When the matcher is encountered for the first time, add it to the map
                    detectionRuleStore = new DetectionRuleStore<>(matcher, visited < n);
                    rulesMap.put(currentMatcherID, detectionRuleStore);
                } else {
                    // When a matcher has already been visited, pass
                    continue;
                }

                // Check all the parameters and their depending detection rules
                for (Parameter<T> parameter : getParameters(currentRule)) {
                    List<String> dependingRuleIDs = new LinkedList<>();

                    List<IDetectionRule<T>> currentDependingRules = parameter.getDetectionRules();
                    for (IDetectionRule<T> currentDependingRule : currentDependingRules) {
                        MethodMatcher<T> currentDependingMatcher = getMatcher(currentDependingRule);
                        if (currentDependingMatcher != null) {
                            String currentDependingMatcherID =
                                    DetectionRuleStore.getMatcherID(currentDependingMatcher);

                            dependingRuleIDs.add(currentDependingMatcherID);
                            rulesToVisit.add(currentDependingRule);
                        }
                    }
                    detectionRuleStore.addParameterDependingRuleIDs(
                            parameter.getParameterType(), dependingRuleIDs);
                }

                // Check the top level depending detection rules
                List<String> dependingRuleIDs = new LinkedList<>();
                for (IDetectionRule<T> currentDependingRule : getNextDetectionRules(currentRule)) {
                    MethodMatcher<T> currentDependingMatcher = getMatcher(currentDependingRule);
                    if (currentDependingMatcher != null) {
                        String currentDependingMatcherID =
                                DetectionRuleStore.getMatcherID(currentDependingMatcher);

                        dependingRuleIDs.add(currentDependingMatcherID);
                        rulesToVisit.add(currentDependingRule);
                    }
                }
                detectionRuleStore.addDependingRuleIDs(dependingRuleIDs);
            }
            visited += 1;
        }

        LOGGER.info("Number of nodes: " + rulesMap.values().size());
        return new ArrayList<>(rulesMap.values());
    }

    private <T> MethodMatcher<T> getMatcher(IDetectionRule<T> rule) {
        if (rule instanceof DetectionRule<T> detectionRule) {
            return detectionRule.matchers();
        } else if (rule instanceof MethodDetectionRule<T> methodDetectionRule) {
            return methodDetectionRule.matchers();
        }
        return null;
    }

    private <T> List<Parameter<T>> getParameters(IDetectionRule<T> rule) {
        if (rule instanceof DetectionRule<T> detectionRule) {
            return detectionRule.parameters();
        }
        return new LinkedList<>();
    }

    private <T> List<IDetectionRule<T>> getNextDetectionRules(IDetectionRule<T> rule) {
        if (rule instanceof DetectionRule<T> detectionRule) {
            return detectionRule.nextDetectionRules();
        } else if (rule instanceof MethodDetectionRule<T> methodDetectionRule) {
            return methodDetectionRule.nextDetectionRules();
        }
        return new LinkedList<>();
    }
}
