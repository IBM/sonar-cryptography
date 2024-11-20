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
package com.ibm.engine.language.python;

import com.ibm.engine.language.IScanContext;
import javax.annotation.Nonnull;
import org.sonar.api.batch.fs.InputFile;
import org.sonar.plugins.python.api.IssueLocation;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonCheck.PreciseIssue;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.tree.*;

public record PythonScanContext(@Nonnull PythonVisitorContext pythonVisitorContext)
        implements IScanContext<PythonCheck, Tree> {

    @Override
    public void reportIssue(
            @Nonnull PythonCheck currentRule, @Nonnull Tree tree, @Nonnull String message) {
        PreciseIssue newIssue =
                new PreciseIssue(currentRule, IssueLocation.preciseLocation(tree, message));
        pythonVisitorContext.addIssue(newIssue);
    }

    @Override
    public @Nonnull InputFile getInputFile() {
        // There is no trivial way to get the InputFile from the `pythonVisitorContext`.
        // Using `.pythonFile()` does not return the correct format, and there doesn't
        // seem to be a converter.
        throw new UnsupportedOperationException("Unimplemented method 'getInputFile'");
    }

    @Override
    public @Nonnull String getFilePath() {
        return pythonVisitorContext.pythonFile().uri().getPath();
    }
}
