package com.ibm.rules;

import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Tag;
import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public final class NoMD5UseForMessageDigestRuleTest extends TestBase {

    @Test
    public void non() {
        final RSA rsa = new RSA(detectionLocation);

        final NoMD5UseForMessageDigestRule<IMockTree> rule = new NoMD5UseForMessageDigestRule<>();
        final List<Issue<IMockTree>> issues = rule.report(new MockTree(), List.of(rsa));

        assertThat(issues).isEmpty();
    }

    @Test
    public void valid() {
        final MD5 md5 = new MD5(detectionLocation);
        md5.put(new Tag(detectionLocation));

        final NoMD5UseForMessageDigestRule<IMockTree> rule = new NoMD5UseForMessageDigestRule<>();
        final List<Issue<IMockTree>> issues = rule.report(new MockTree(), List.of(md5));

        assertThat(issues).isEmpty();
    }

    @Test
    public void inValid() {
        final MD5 md5 = new MD5(detectionLocation);
        md5.put(new Digest(detectionLocation));

        final NoMD5UseForMessageDigestRule<IMockTree> rule = new NoMD5UseForMessageDigestRule<>();
        final List<Issue<IMockTree>> issues = rule.report(new MockTree(), List.of(md5));

        assertThat(issues).hasSize(1);
    }

}
