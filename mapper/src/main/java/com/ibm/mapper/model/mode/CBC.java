package com.ibm.mapper.model.mode;

import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class CBC extends Mode {

    public CBC(@NotNull DetectionLocation detectionLocation) {
        super("CBC", detectionLocation);
    }
}
