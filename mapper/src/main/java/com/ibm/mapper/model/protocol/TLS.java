package com.ibm.mapper.model.protocol;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Protocol;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.collections.CipherSuiteCollection;
import com.ibm.mapper.utils.DetectionLocation;
import org.jetbrains.annotations.NotNull;

import javax.annotation.Nonnull;
import java.util.Optional;


public final class TLS extends Protocol {

    public TLS(@NotNull DetectionLocation detectionLocation) {
        super("TLS", detectionLocation);
    }

    public TLS(@Nonnull Version version) {
        super("TLSv" + version.asString(), version.getDetectionContext());
        this.append(version);
    }

    @Nonnull
    public Optional<Version> getVersion() {
        INode node = this.getChildren().get(Version.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((Version) node);
    }

    @Nonnull
    public Optional<CipherSuiteCollection> getCipherSuits() {
        INode node = this.getChildren().get(CipherSuiteCollection.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((CipherSuiteCollection) node);
    }
}
