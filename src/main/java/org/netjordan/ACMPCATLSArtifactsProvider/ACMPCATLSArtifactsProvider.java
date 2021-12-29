package org.netjordan.ACMPCATLSArtifactsProvider;

import com.amazonaws.services.acmpca.AWSACMPCA;
import com.amazonaws.services.acmpca.AWSACMPCAClientBuilder;
import com.amazonaws.services.acmpca.model.InvalidNextTokenException;
import com.amazonaws.services.acmpca.model.ListCertificateAuthoritiesRequest;
import com.amazonaws.services.acmpca.model.ListCertificateAuthoritiesResult;
import com.amazonaws.services.elasticmapreduce.spi.security.TLSArtifacts;
import com.amazonaws.services.elasticmapreduce.spi.security.TLSArtifactsProvider;

public class ACMPCATLSArtifactsProvider extends TLSArtifactsProvider {
    AWSACMPCA awsAcmPce;

    public ACMPCATLSArtifactsProvider() {
        this.awsAcmPce = AWSACMPCAClientBuilder.standard().build();
    }

    @Override
    public TLSArtifacts getTlsArtifacts() {
        return null;
    }

    public void listCertificateAuthorities() {
        ListCertificateAuthoritiesRequest listCertificateAuthoritiesRequest = new ListCertificateAuthoritiesRequest();
        listCertificateAuthoritiesRequest.withMaxResults(1);

        // Retrieve a list of your CAs.
        ListCertificateAuthoritiesResult listCertificateAuthoritiesResult = null;
        try {
            listCertificateAuthoritiesResult = awsAcmPce.listCertificateAuthorities(listCertificateAuthoritiesRequest);
        } catch (InvalidNextTokenException ex) {
            throw ex;
        }

        // Display the CA list.
        System.out.println(listCertificateAuthoritiesResult.getCertificateAuthorities());
    }
}
