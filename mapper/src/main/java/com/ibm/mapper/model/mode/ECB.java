package com.ibm.mapper.model.mode;

import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class ECB extends Mode {

    public ECB(@NotNull DetectionLocation detectionLocation) {
        super("ECB", detectionLocation);
    }
}
