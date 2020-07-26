import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.x500.X500Principal;


import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

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
            //String strPrivateCAStore = strPrivateJavaHome + "/lib/security/cacerts";
            String strPrivateCAStore = "cacerts";

            FileInputStream bIn = new FileInputStream(strPrivateCAStore);
            caks.load(bIn, "changeit".toCharArray());
            bIn.close();

            X509Certificate cert = (X509Certificate) caks.getCertificate("dualultimateca");
            // this is a correct CA cert
            if (cert.getBasicConstraints() >= 0)
                return;
/*
            KeyStore.PrivateKeyEntry privateKey = (KeyStore.PrivateKeyEntry) caks.getEntry(
                    "dualultimateca", new KeyStore.PasswordProtection("".toCharArray()));
            caPrivKey = privateKey.getPrivateKey();
*/
            // key has no password
            caPrivKey = (PrivateKey) caks.getKey("dualultimateca", "".toCharArray());
            caPubKey = cert.getPublicKey();


            String algName = cert.getSigAlgName();
            //Use appropriate signature algorithm based on your keyPair algorithm
            final ContentSigner contentSigner = new JcaContentSignerBuilder(algName).build(caPrivKey);
            final X500Name x500Name = getSubjectX500Name(cert);
            JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
            final X509v3CertificateBuilder certificateBuilder =
                    new JcaX509v3CertificateBuilder(x500Name,
                            cert.getSerialNumber(),
                            cert.getNotBefore(),
                            cert.getNotAfter(),
                            x500Name,
                            caPubKey)

                            .addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(caPubKey))
                            .addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(caPubKey))
                            .addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.digitalSignature))
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

    /*
    https://stackoverflow.com/questions/7567837/attributes-reversed-in-certificate-subject-and-issuer
     //create a X500Name (bouncy) from a X500Principal (SUN)
     */
    private static X500Name toBouncyX500Name( javax.security.auth.x500.X500Principal principal) {

        String name = principal.getName();

        String[] RDN = name.split(",");

        StringBuffer buf = new StringBuffer(name.length());
        for(int i = RDN.length - 1; i >= 0; i--){
            if(i != RDN.length - 1)
                buf.append(',');

            buf.append(RDN[i]);
        }

        return new X500Name(buf.toString());
    }

    public static X500Name getSubjectX500Name(X509Certificate cert) {
        Principal subjectDN = cert.getSubjectDN();
        if (subjectDN instanceof X500Name) {
            return (X500Name)subjectDN;
        } else {
            X500Principal subjectX500 = cert.getSubjectX500Principal();
            return toBouncyX500Name(subjectX500);
            //return new X500Name(subjectX500.getName(X500Principal.RFC2253));    // we use RFC2253 order
        }
    }


}
