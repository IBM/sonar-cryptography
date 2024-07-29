package com.ibm.mapper.model.mode;

import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

public final class CTS extends Mode {

    public CTS(@NotNull DetectionLocation detectionLocation) {
        super("CTS", detectionLocation);
    }
}
