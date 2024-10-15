package com.ibm.rules;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.utils.DetectionLocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;

public abstract class TestBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(TestBase.class);

    protected final String filePath = "test.java";
    protected final int lineNumber = 1;
    protected final int offset = 1;
    protected final IBundle bundle = () -> "Test";
    protected final DetectionLocation detectionLocation =
            new DetectionLocation(filePath, lineNumber, offset, Collections.emptyList(), bundle);
}
