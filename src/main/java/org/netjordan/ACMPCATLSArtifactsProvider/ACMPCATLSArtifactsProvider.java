package org.netjordan.ACMPCATLSArtifactsProvider;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.acmpca.AWSACMPCA;
import com.amazonaws.services.acmpca.AWSACMPCAClient;
import com.amazonaws.services.acmpca.model.*;
import com.amazonaws.services.elasticmapreduce.spi.security.TLSArtifacts;
import com.amazonaws.services.elasticmapreduce.spi.security.TLSArtifactsProvider;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.io.StringReader;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class ACMPCATLSArtifactsProvider extends TLSArtifactsProvider {
    AWSACMPCA awsAcmPce;
    private static final long CERTIFICATE_VALIDITY_DAYS = 30L;

    public ACMPCATLSArtifactsProvider() {
        // TODO: use default region
        this.awsAcmPce = AWSACMPCAClient.builder().withRegion(Regions.EU_WEST_2).build();
    }

    @Override
    public TLSArtifacts getTlsArtifacts() {
        // get the first certificate authority
        List<CertificateAuthority> certificateAuthorityList = listCertificateAuthorities();
        CertificateAuthority certificateAuthority = certificateAuthorityList.get(0);

        Validity validity = new Validity()
                .withType("DAYS")
                .withValue(ACMPCATLSArtifactsProvider.CERTIFICATE_VALIDITY_DAYS);

        KeyPair keyPair = this.generateKeyPair();

        ByteBuffer csr = null;
        try {
            csr = this.generateCSR(keyPair);
        } catch (Exception e) {
            e.printStackTrace();
        }

        IssueCertificateRequest issueCertificateRequest = new IssueCertificateRequest()
                .withCertificateAuthorityArn(certificateAuthority.getArn())
                .withSigningAlgorithm(SigningAlgorithm.SHA256WITHRSA)
                .withValidity(validity)
                .withCsr(csr)
                .withIdempotencyToken("1234");

        IssueCertificateResult issueCertificateResult = null;

        try {
            issueCertificateResult = awsAcmPce.issueCertificate(issueCertificateRequest);
        } catch (Exception ex) {
            throw ex;
        }

        // convert the returned certificate from a string into a List<Certificate>
        List<X509Certificate> certificateList = this.convertToCertificateList(
                this.getCertificate(issueCertificateResult.getCertificateArn())
        );

        TLSArtifacts tlsArtifacts = new TLSArtifacts(keyPair.getPrivate(), certificateList);


        return null;
    }

    public String getCertificate(String certificateAuthorityArn) {
        GetCertificateRequest getCertificateRequest = new GetCertificateRequest()
                .withCertificateArn(certificateArn)
                .withCertificateAuthorityArn(certificateAuthorityArn);

        GetCertificateResult getCertificateResult = null;
        try {
            getCertificateResult = awsAcmPce.getCertificate(getCertificateRequest);
        } catch (Exception ex) {
            throw ex;
        }

        return null;
    }

    public List<X509Certificate> convertToCertificateList(String certificateString) {
        // convert base64 pem encoded cert to Certificate
        StringReader stringReader = new StringReader(certificateString);
        PEMParser pemParser = new PEMParser(stringReader);
        JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();

        List<X509Certificate> x509CertificateList = new ArrayList<X509Certificate>();

        Object object = null;

        try {
            while ((object = pemParser.readObject()) != null) {
                if (object instanceof X509CertificateHolder) x509CertificateList.add(
                        (X509Certificate) jcaX509CertificateConverter.getCertificate((X509CertificateHolder) object)
                );
            }
        }
        catch (Exception ex) {
            ex.printStackTrace();
        }

        return x509CertificateList;
    }

    public List<CertificateAuthority> listCertificateAuthorities() {
        ListCertificateAuthoritiesRequest listCertificateAuthoritiesRequest = new ListCertificateAuthoritiesRequest()
                .withResourceOwner(ResourceOwner.OTHER_ACCOUNTS);
        listCertificateAuthoritiesRequest.withMaxResults(100);

        // Retrieve a list of your CAs.
        ListCertificateAuthoritiesResult listCertificateAuthoritiesResult = null;
        try {
            listCertificateAuthoritiesResult = awsAcmPce.listCertificateAuthorities(listCertificateAuthoritiesRequest);
        } catch (InvalidNextTokenException ex) {
            throw ex;
        }

        // Display the CA list.
        return listCertificateAuthoritiesResult.getCertificateAuthorities();
    }

    public KeyPair generateKeyPair() {
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        }
        catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }

        keyPairGenerator.initialize(2048, new SecureRandom());

        return keyPairGenerator.generateKeyPair();
    }

    public ByteBuffer generateCSR(KeyPair keyPair) throws OperatorCreationException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // TODO: use region in the common name
        X500Principal x500Principal = new X500Principal("CN=*.compute.internal.");

        PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(
                x500Principal,
                keyPair.getPublic()
        );

        ArrayList<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.id_kp_clientAuth);
        keyPurposeIds.add(KeyPurposeId.id_kp_serverAuth);

        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(keyPurposeIds.toArray(new KeyPurposeId[keyPurposeIds.size()]));

        ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(Extension.extendedKeyUsage, true, extendedKeyUsage);
        pkcs10CertificationRequestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());

        JcaContentSignerBuilder jcaContentSignerBuilder = new JcaContentSignerBuilder("SHA256withRSA");
        ContentSigner contentSigner = jcaContentSignerBuilder.build(keyPair.getPrivate());
        PKCS10CertificationRequest pkcs10CertificationRequest = pkcs10CertificationRequestBuilder.build(contentSigner);

//        StringWriter stringWriter = new StringWriter();
//        JcaPEMWriter jcaPEMWriter = new JcaPEMWriter(stringWriter);
//        jcaPEMWriter.writeObject(pkcs10CertificationRequest);
//        jcaPEMWriter.close();
//        System.out.println(stringWriter.getBuffer());

        return ByteBuffer.wrap(pkcs10CertificationRequest.getEncoded());
    }
}
