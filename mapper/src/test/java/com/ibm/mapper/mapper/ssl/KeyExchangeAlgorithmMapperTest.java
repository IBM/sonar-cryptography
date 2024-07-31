package com.ibm.mapper.mapper.ssl;

import com.ibm.mapper.mapper.ssl.json.JsonCipherSuite;
import com.ibm.mapper.mapper.ssl.json.JsonCipherSuites;
import com.ibm.mapper.utils.DetectionLocation;
import org.junit.Test;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

public class KeyExchangeAlgorithmMapperTest {

    @Test
    public void test() {
        final DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));

        final KeyExchangeAlgorithmMapper mapper = new KeyExchangeAlgorithmMapper();
        final Collection<String> kexCollection =
                JsonCipherSuites.CIPHER_SUITES.values().stream()
                        .map(JsonCipherSuite::getKexAlgorithm)
                        .filter(Optional::isPresent)
                        .map(Optional::get)
                        .collect(Collectors.toSet());

        for (String kex : kexCollection) {
            if (Objects.equals(kex, "NULL")) {
                continue;
            }

            try {
                assertThat(mapper.parse(kex, testDetectionLocation)).isPresent();
            } catch (AssertionError e) {
                System.out.println("Can't map '" + kex + "'");
                throw e;
            }
        }
    }
}
