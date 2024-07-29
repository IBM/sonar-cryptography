package com.ibm.mapper.mapper.jca;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.algorithms.ECDH;
import com.ibm.mapper.model.algorithms.XDH;
import com.ibm.mapper.model.algorithms.x25519;
import com.ibm.mapper.model.algorithms.x448;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Optional;

public class JcaKeyAgreementMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<KeyAgreement> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        return switch (str.toUpperCase().trim()) {
            case "ECDH" -> Optional.of(new ECDH(detectionLocation));
            case "X25519" -> Optional.of(new x25519(detectionLocation));
            case "X448" -> Optional.of(new x448(detectionLocation));
            case "XDH" -> Optional.of(new XDH(detectionLocation));
            default -> Optional.empty();
        };
    }
}
