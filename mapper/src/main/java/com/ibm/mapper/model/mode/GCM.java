package com.ibm.mapper.model.mode;

import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class GCM extends Mode {

    public GCM(@NotNull DetectionLocation detectionLocation) {
        super("GCM", detectionLocation);
    }
}
