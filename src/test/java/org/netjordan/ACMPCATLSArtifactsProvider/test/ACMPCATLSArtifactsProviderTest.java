package org.netjordan.ACMPCATLSArtifactsProvider.test;

import com.amazonaws.services.elasticmapreduce.spi.security.TLSArtifacts;
import com.amazonaws.services.elasticmapreduce.spi.security.TLSArtifactsProvider;
import org.junit.Test;
import org.netjordan.ACMPCATLSArtifactsProvider.ACMPCATLSArtifactsProvider;

public class ACMPCATLSArtifactsProviderTest {
    ACMPCATLSArtifactsProvider acmpcatlsArtifactsProvider;

    public ACMPCATLSArtifactsProviderTest() {
        this.acmpcatlsArtifactsProvider = new ACMPCATLSArtifactsProvider();
    }

    @Test
    public void testCanListPCAProviders() {
        this.acmpcatlsArtifactsProvider.listCertificateAuthorities();
    }

    @Test
    public void testCanGetTLSArtifacts() {

        TLSArtifacts tls = this.tlsArtifactsProvider.getTlsArtifacts();
    }



}
