import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import javax.security.cert.CertificateParsingException;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;

public class RenewUltimateCA {
    public static void main(String[] args) {
        System.out.println("Hello World !!");

        //get CA cert, private key and publick key first
        Certificate caDUALCert;
        PrivateKey caPrivKey;
        PublicKey caPubKey;
        String strPrivateJavaHome = "";

        try {
            KeyStore caks = KeyStore.getInstance("JKS");
            //        String javaHome = System.getProperty("java.home");
            String strPrivateCAStore = strPrivateJavaHome + "/lib/security/cacerts";

            FileInputStream bIn = new FileInputStream(strPrivateCAStore);
            caks.load(bIn, "changeit".toCharArray());
            bIn.close();

            caDUALCert = caks.getCertificate("dualultimateca");
            caPrivKey = (PrivateKey) caks.getKey("dualultimateca", "changeit".toCharArray());
            caPubKey = caDUALCert.getPublicKey();

            X509Certificate cert = (X509Certificate) caDUALCert;
            // this is a correct CA cert
            if (cert.getBasicConstraints() < 0)
                return;


            String algName = cert.getSigAlgName();
            //Use appropriate signature algorithm based on your keyPair algorithm
            final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(caPrivKey);
            final X500Name x500Name = getSubjectX500Name(cert);
            final X509v3CertificateBuilder certificateBuilder =
                    new JcaX509v3CertificateBuilder(x500Name,
                            cert.getSerialNumber(),
                            cert.getNotBefore(),
                            cert.getNotAfter(),
                            x500Name,
                            caPubKey)
                            //                       .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(caPubKey))
                            //                       .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(caPubKey))
                            .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

            //new cert
            cert = new JcaX509CertificateConverter()
                    .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));


            // set the entries
            //        caCerts.setCertificateEntry("DUAL Ultimate", cert);
            Certificate[] chain = new Certificate[1];
            chain[0] = cert;

            caks.setKeyEntry("dualultimateca", caPrivKey, "changeit".toCharArray(), chain);

            //replace the old one in cacerts
            FileOutputStream bOut = new FileOutputStream(strPrivateCAStore);
            caks.store(bOut, "changeit".toCharArray());
            bOut.close();
        }
        catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }


    public static X500Name getSubjectX500Name(X509Certificate cert) {
        Principal subjectDN = cert.getSubjectDN();
        if (subjectDN instanceof X500Name) {
            return (X500Name)subjectDN;
        } else {
            X500Principal subjectX500 = cert.getSubjectX500Principal();
            return new X500Name(subjectX500.getName(X500Principal.RFC1779));
        }
    }


}
