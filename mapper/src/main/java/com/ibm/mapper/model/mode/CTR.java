package com.ibm.mapper.model.mode;

import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class CTR extends Mode {

    public CTR(@NotNull DetectionLocation detectionLocation) {
        super("CTR", detectionLocation);
    }
}
