package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import java.util.Optional;

/**
 *
 *
 * <h2>{@value #NAME}</h2>
 *
 * <p>
 *
 * <h3>Specification</h3>
 *
 * <ul>
 *   <li>https://csrc.nist.gov/pubs/fips/203/final
 * </ul>
 *
 * <h3>Other Names and Related Standards</h3>
 *
 * <ul>
 *   <li>Module-Lattice-Based Digital Signature
 *   <li>Standardized version of Dilithium
 * </ul>
 */
public class MLDSA extends Algorithm implements Signature {
    private static final String NAME = "ML-DSA";

    /** Returns a name of the form "ML-DSA-XXX" where XXX is the parameter set identifer */
    @Override
    @Nonnull
    public String asString() {
        StringBuilder builtName = new StringBuilder(this.hasChildOfType(MessageDigest.class)
                .map(node -> node.asString() + "with" + this.name)
                .orElse(this.name));
        Optional<INode> parameterSetIdentifier = this.hasChildOfType(ParameterSetIdentifier.class);
        parameterSetIdentifier.ifPresent(node -> builtName.append("-").append(node.asString()));
        return builtName.toString();
    }

    protected MLDSA(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, Signature.class, detectionLocation);
    }

    public MLDSA(@Nonnull MessageDigest preHash, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(preHash);
    }


    public MLDSA(int parameterSetIdentifier, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(
                new ParameterSetIdentifier(
                        String.valueOf(parameterSetIdentifier), detectionLocation));
    }
}
