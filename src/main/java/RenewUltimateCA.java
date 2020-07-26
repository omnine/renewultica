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

        KeyStore caks = KeyStore.getInstance("JKS");
        //        String javaHome = System.getProperty("java.home");
        String strPrivateCAStore = strPrivateJavaHome + "/lib/security/cacerts";
        caks.load(new FileInputStream(strPrivateCAStore), "changeit".toCharArray());

        caDUALCert = caks.getCertificate("dualultimateca");
        caPrivKey = (PrivateKey) caks.getKey("dualultimateca", "changeit".toCharArray());
        caPubKey = caDUALCert.getPublicKey();

        X509Certificate cert = (X509Certificate)caDUALCert;
        // this is a correct CA cert
        if(cert.getBasicConstraints() < 0)
            return;

        cert.getIssuerDN()

        final Instant now = Instant.now();
        final Date notBefore = Date.from(now);
        final Date notAfter = Date.from(now.plus(Duration.ofDays(days)));

        //Use appropriate signature algorithm based on your keyPair algorithm
        final ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(caPrivKey);
        final X500Name x500Name = getSubjectX500Name(cert);
        final X509v3CertificateBuilder certificateBuilder =
                new JcaX509v3CertificateBuilder(x500Name,
                        BigInteger.valueOf(now.toEpochMilli()),
                        notBefore,
                        notAfter,
                        x500Name,
                        caPubKey)
 //                       .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(caPubKey))
 //                       .addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(caPubKey))
                        .addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

        return new JcaX509CertificateConverter()
                .setProvider(new BouncyCastleProvider()).getCertificate(certificateBuilder.build(contentSigner));
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


    public static Certificate selfSign(KeyPair keyPair, String subjectDN) throws OperatorCreationException, CertificateException, IOException
    {
        Provider bcProvider = new BouncyCastleProvider();
        Security.addProvider(bcProvider);

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);

        X500Name dnName = new X500Name(subjectDN);
        BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(startDate);
        calendar.add(Calendar.YEAR, 1); // <-- 1 Yr validity

        Date endDate = calendar.getTime();

        String signatureAlgorithm = "SHA256WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

        // Extensions --------------------------



        // -------------------------------------

        return new JcaX509CertificateConverter().setProvider(bcProvider).getCertificate(certBuilder.build(contentSigner));
    }

    public static boolean createMasterCert(String strPrivateJavaHome,  String strSeed,    PublicKey       pubKey,
                                           PrivateKey      privKey)
    {
        boolean bret = true;
        try
        {
            X509V3CertificateGenerator v3CertGen2 = new X509V3CertificateGenerator();
            //
            // signers name
            //
            String  issuer = "C=UK, O=Deepnet Security, OU=" + strSeed;

            //
            // subjects name - the same as we are self signed.
            //
            String  subject = issuer;

            //
            // create the certificate - version 1
            //

            v3CertGen2.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
            v3CertGen2.setIssuerDN(new X509Principal(issuer));
            v3CertGen2.setNotBefore(new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30));	// one month
            v3CertGen2.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 30 * 1200 ))); // 10 years
            v3CertGen2.setSubjectDN(new X509Principal(subject));
            v3CertGen2.setPublicKey(pubKey);
            v3CertGen2.setSignatureAlgorithm("SHA256WithRSAEncryption");

            v3CertGen2.addExtension(
                    org.bouncycastle.asn1.x509.X509Extensions.BasicConstraints,
                    true,
                    new org.bouncycastle.asn1.x509.BasicConstraints(true)
            );

            //       X509Certificate cert = v1CertGen.generateX509Certificate(privKey);
            X509Certificate cert = v3CertGen2.generate(privKey,"BC");

            cert.checkValidity(new Date());

            cert.verify(pubKey);

            //		now write it to cacerts store
            KeyStore caCerts = KeyStore.getInstance("JKS");
            //        String javaHome = System.getProperty("java.home");
            String strPrivateCAStore = strPrivateJavaHome + "/lib/security/cacerts";
            caCerts.load(new FileInputStream(strPrivateCAStore),
                    "changeit".toCharArray());

            // set the entries
            //        caCerts.setCertificateEntry("DUAL Ultimate", cert);
            Certificate[] chain = new Certificate[1];
            chain[0] = cert;

            caCerts.setKeyEntry("dualultimateca", privKey, "changeit".toCharArray(), chain);

            FileOutputStream bOut = new FileOutputStream(strPrivateCAStore);
            caCerts.store(bOut, "changeit".toCharArray());
            bOut.close();
        }
        catch(Exception e)
        {
            e.printStackTrace();
            bret = false;
        }

        return bret;
    }



}
