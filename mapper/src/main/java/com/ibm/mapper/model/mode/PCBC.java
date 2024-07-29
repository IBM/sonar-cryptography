package com.ibm.mapper.model.mode;

import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class PCBC extends Mode {

    public PCBC(@NotNull DetectionLocation detectionLocation) {
        super("PCBC", detectionLocation);
    }
}
