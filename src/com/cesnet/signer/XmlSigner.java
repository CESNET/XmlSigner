package com.cesnet.signer;

import au.csiro.nt.pdsp.util.X509KeySelector;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Constructor;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class XmlSigner {

    private KeyStore keyStore;
    private char[] pin;
    private String inputFile = null;
    private String outputFile = null;
    private String cfgFile = null;
    private String signingAlias = null;
    private String providerClass = "sun.security.pkcs11.SunPKCS11";
    private String providerType = "PKCS11";
    private String providerConfig = null;
    private boolean infoOnly = false;

    public void sign(Node node, String signer) throws Exception {
        if (signer == null) {
            throw new IllegalArgumentException("Missing signer");
        }

        if (node == null) {
            throw new IllegalArgumentException("Not signing empty document");
        }

        PrivateKey signerKey = (PrivateKey) this.keyStore.getKey(signer, this.pin);
        if (signerKey == null) {
            throw new IllegalArgumentException("No such signer: " + signer);
        }

        X509Certificate certificate = (X509Certificate) this.keyStore.getCertificate(signer);
        assert (node != null);
        Node firstChild = node.getFirstChild();
        assert (firstChild != null);
        DOMSignContext dsc = new DOMSignContext(signerKey, node, firstChild);
        String providerName = System.getProperty("jsr105Provider", "org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM", (Provider) Class.forName(providerName).newInstance());

        Reference ref = fac.newReference("", fac.newDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1", null), Collections.singletonList(fac.newTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature", (TransformParameterSpec) null)), null, null);

        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", (C14NMethodParameterSpec) null), fac.newSignatureMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1", null), Collections.singletonList(ref));

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        X509Data xd = kif.newX509Data(Collections.singletonList(certificate));
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
        XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);
    }

    public boolean sign2(String signer, String xmlInFile, String xmlOutFile) throws Exception {
        if (signer == null) {
            System.err.println("Error: Missing signer");
            System.exit(3);
        }

        PrivateKey signerKey = (PrivateKey) this.keyStore.getKey(signer, this.pin);
        if (signerKey == null) {
            System.err.println("Error: No such signer: " + signer);
            System.exit(3);
        }

        X509Certificate certificate = (X509Certificate) this.keyStore.getCertificate(signer);
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref = fac.newReference("", fac.newDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1", null), Collections.singletonList(fac.newTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature", (TransformParameterSpec) null)), null, null);

        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", (C14NMethodParameterSpec) null), fac.newSignatureMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1", null), Collections.singletonList(ref));

        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.add(certificate.getSubjectX500Principal().getName());
        x509Content.add(certificate);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = null;
        try {
            doc = dbf.newDocumentBuilder().parse(new FileInputStream(xmlInFile));
        } catch (IOException e) {
            System.err.println("Error: Cannot open input file " + xmlInFile);
            System.exit(3);
        }

        Node firstChild = doc.getDocumentElement().getFirstChild();
        DOMSignContext dsc = new DOMSignContext(signerKey, doc.getDocumentElement(), firstChild);

        XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);
        OutputStream os = new FileOutputStream(xmlOutFile);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));

        Document doc2 = null;
        try {
            doc2 = dbf.newDocumentBuilder().parse(new FileInputStream(xmlOutFile));
        } catch (IOException e) {
            System.err.println("Error: Cannot open output file for validation " + xmlOutFile);
            System.exit(3);
        }
        NodeList nl = doc2.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        if (nl.getLength() == 0) {
            System.err.println("Error: Validation fails - cannot find Signature element");
            System.exit(4);
        }
        DOMValidateContext valContext = new DOMValidateContext(new X509KeySelector(), nl.item(0));
        XMLSignature signature2 = fac.unmarshalXMLSignature(valContext);
        boolean coreValidity = signature2.validate(valContext);
        return coreValidity;
    }

    public void signJKS(String keyStoreFile, String keystorePassword, String signer, String xmlInFile, String xmlOutFile) throws Exception {
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref = fac.newReference("", fac.newDigestMethod("http://www.w3.org/2000/09/xmldsig#sha1", null), Collections.singletonList(fac.newTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature", (TransformParameterSpec) null)), null, null);

        SignedInfo si = fac.newSignedInfo(fac.newCanonicalizationMethod("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", (C14NMethodParameterSpec) null), fac.newSignatureMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1", null), Collections.singletonList(ref));

        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keyStoreFile), keystorePassword.toCharArray());
        KeyStore.PrivateKeyEntry keyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(signer, new KeyStore.PasswordProtection(keystorePassword.toCharArray()));

        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        List x509Content = new ArrayList();
        x509Content.add(cert.getSubjectX500Principal().getName());
        x509Content.add(cert);
        X509Data xd = kif.newX509Data(x509Content);
        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(xmlInFile));

        DOMSignContext dsc = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());
        XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);
        OutputStream os = new FileOutputStream(xmlOutFile);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));
    }

    public final void initialize(String providerClassName, String providerType, String configName, String keyStoreLocation, char[] pin) throws Exception {
        if ((providerClassName != null) && (providerClassName.length() > 0)) {
            Class providerClass = Class.forName(providerClassName);
            Provider cryptoProvider = null;
            Constructor constructor = providerClass.getConstructor(new Class[]{String.class});
            if ((configName != null) && (configName.length() > 0)) {
                cryptoProvider = (Provider) constructor.newInstance(new Object[]{configName});
            } else {
                cryptoProvider = (Provider) providerClass.newInstance();
            }

            assert (cryptoProvider != null);
            int pos = Security.addProvider(cryptoProvider);
            if (this.infoOnly) {
                System.out.println("Setting provider, position " + pos);
            }

        }

        this.keyStore = KeyStore.getInstance(providerType);
        InputStream ksIn = null;
        if ((keyStoreLocation != null) && (keyStoreLocation.length() > 0)) {
            File ksFile = new File(keyStoreLocation);
            ksIn = new FileInputStream(ksFile);
        }
        if (this.infoOnly) {
            Provider[] providers = Security.getProviders();
            int prolen = providers.length;
            System.out.println("Provider list (" + prolen + " found):\n");
            for (Provider p : providers) {
                System.out.println("    " + p.getName() + " (ver. " + p.getVersion() + ") - " + p.size() + " entries\n");
                Set services = p.getServices();
                Iterator it = services.iterator();
                System.out.println("        Services:");
                while (it.hasNext()) {
                    Provider.Service ps = (Provider.Service) it.next();
                    ps.getType();
                    ps.getAlgorithm();
                    ps.getClassName();
                    System.out.println("            " + ps.getType() + " - " + ps.getAlgorithm() + " - " + ps.getClassName());
                }
                System.out.println();
                System.out.println("        Setup:");
                Enumeration keys = p.keys();

                String info = p.getInfo();

                while (keys.hasMoreElements()) {
                    Object key = keys.nextElement();
                    Object value = p.get(key);
                    System.out.println("            " + key.toString() + " = " + value.toString());
                }
                System.out.println();
            }
        }
        this.keyStore.load(ksIn, pin);
    }

    public void printInfo() throws KeyStoreException {
        int size = this.keyStore.size();
        System.out.println("Entries in keystore: " + size);

        String providerName = this.keyStore.getProvider().getName();
        System.out.println("Provider name: " + providerName);

        String providerType = this.keyStore.getType();
        System.out.println("Provider type: " + providerType + "\n");

        Enumeration aliases = this.keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = (String) aliases.nextElement();
            if (this.keyStore.isCertificateEntry(alias)) {
                System.out.println("Alias (certificate): " + alias);
                Certificate cert = this.keyStore.getCertificate(alias);
                System.out.println("Cert: " + cert.toString());
                System.out.println();
            } else if (this.keyStore.isCertificateEntry(alias)) {
                System.out.println("Alias (key): " + alias);
                System.out.println();
            } else {
                System.out.println("Alias (unknown type): " + alias);
                Certificate[] certChain = this.keyStore.getCertificateChain(alias);
                for (Certificate cert : certChain) {
                    System.out.println("Cert: " + cert.toString() + "\n\n");
                }
            }
        }
    }

    private void signMetadata() throws Exception {
        Node toBeSigned = readFile(this.inputFile);
        sign(toBeSigned, this.signingAlias);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer t = tf.newTransformer();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        t.transform(new DOMSource(toBeSigned), new StreamResult(baos));
        byte[] bs = baos.toByteArray();
        FileOutputStream out = new FileOutputStream(this.outputFile);
        out.write(bs);
        out.close();
    }

    private void signMetadata2() throws Exception {
        if (!sign2(this.signingAlias, this.inputFile, this.outputFile)) {
            System.err.println("Xml file was signed, but validation failed. Please contact author at jan.chvojka@cesnet.cz");
            System.exit(4);
        }
    }

    private boolean verify(String fileName) throws Exception {
        File file = new File(fileName);
        if (!file.canRead()) {
            throw new IOException("Cannot open file " + fileName);
        }
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.parse(file);

        NodeList nl = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
        if (nl.getLength() == 0) {
            throw new Exception("Cannot find Signature element");
        }
        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        return true;
    }

    private Node readFile(String filename) throws Exception {
        File file = new File(filename);
        if (!file.canRead()) {
            throw new IOException("Cannot open file " + filename);
        }
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(filename));
        return doc.getDocumentElement();
    }

    private void printUsage() {
        StringBuilder sb = new StringBuilder("Usage: XmlSigner -h");
        sb.append("Usage: XmlSigner -h\n");
        sb.append("       XmlSigner -i <input_file.xml> -o <output_file.xml> -cfg <cfg_file>\n\n");
        sb.append("  Sample cfg_file:\n");
        sb.append("      providerclass = sun.security.pkcs11.SunPKCS11\n");
        sb.append("      providertype = PKCS11\n");
        sb.append("      providerconfig = signer.cfg\n");
        sb.append("      pin = mysecretpin\n");
        sb.append("      signingalias = key_alias\n\n");
        sb.append("  Sample providerconfig (signer.cfg) file:");
        sb.append("               name=NFastJava");
        sb.append("               library=/opt/nfast/toolkits/pkcs11/libcknfast.so");
        sb.append("               slotListIndex=1");
        sb.append("               attributes(generate,CKO_PRIVATE_KEY,*) = {");
        sb.append("                   CKA_PRIVATE = true");
        sb.append("                   CKA_SIGN = true");
        sb.append("                   CKA_DECRYPT = true");
        sb.append("                   CKA_TOKEN = true");
        sb.append("               }\n");
        System.out.println(sb.toString());
    }

    private boolean parseParams(String[] args) throws Exception {
        if (args.length == 0) {
            printUsage();
            return false;
        }

        if (args.length == 1) {
            if (args[0].equals("-h")) {
                printUsage();
                return false;
            }
            System.out.println("Wrong parameter: " + args[1]);
            printUsage();
            return false;
        }

        if (args.length == 2) {
            if (args[0].equals("-info")) {
                this.cfgFile = args[1];
                try {
                    if (!loadIniParams(this.cfgFile)) {
                        System.exit(1);
                    }
                } catch (FileNotFoundException e) {
                    System.err.println("Error: Cannot find configuration file " + this.cfgFile);
                    System.exit(1);
                }
                this.infoOnly = true;
                return true;
            }
            System.out.println("Wrong parameter: " + args[1]);
            printUsage();
            return false;
        }

        if (args.length % 2 == 1) {
            System.out.println("Wrong parameter usage.");
            printUsage();
            return false;
        }

        boolean iparam = false;
        boolean oparam = false;
        boolean cfgparam = false;
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-i")) {
                iparam = true;
                i++;
                this.inputFile = args[i];
            } else if (args[i].equals("-o")) {
                oparam = true;
                i++;
                this.outputFile = args[i];
            } else if (args[i].equals("-cfg")) {
                cfgparam = true;
                i++;
                this.cfgFile = args[i];
            }
        }
        if ((!iparam) || (!oparam) || (!cfgparam)) {
            System.out.println("Wrong parameter usage.");
            printUsage();
            return false;
        }
        loadIniParams(this.cfgFile);
        return true;
    }

    private boolean loadIniParams(String iniFileName) throws Exception {
        boolean ret = true;
        Properties p = new Properties();
        p.load(new FileInputStream(iniFileName));
        StringBuffer sb = new StringBuffer();
        String err = "Error: While using configuration file " + iniFileName + " there was error\n";

        String s = p.getProperty("providerclass");
        if (s == null) {
            if (ret) {
                sb.append(err);
            }
            sb.append("Error: Cannot find key \"providerclass\" in config file.\n");
            ret = false;
        } else {
            this.providerClass = s;
        }

        s = p.getProperty("providertype");
        if (s == null) {
            if (ret) {
                sb.append(err);
            }
            sb.append("Error: Cannot find key \"providertype\" in config file.\n");
            ret = false;
        } else {
            this.providerType = s;
        }

        s = p.getProperty("providerconfig");
        if (s == null) {
            if (ret) {
                sb.append(err);
            }
            sb.append("Error: Cannot find key \"providerconfig\" in config file.\n");
            ret = false;
        } else {
            this.providerConfig = s;
        }

        s = p.getProperty("pin");
        if (s == null) {
            if (ret) {
                sb.append(err);
            }
            sb.append("Error: Cannot find key \"pin\" in config file.\n");
            ret = false;
        } else {
            this.pin = s.toCharArray();
        }

        s = p.getProperty("signingalias");
        if (s == null) {
            if (ret) {
                sb.append(err);
            }
            sb.append("Error: Cannot find key \"signingalias\" in config file.\n");
            ret = false;
        } else {
            this.signingAlias = s;
        }

        if (!ret) {
            System.err.println(sb.toString());
        }
        return ret;
    }

    public static void main(String[] args) {
        XmlSigner xs = new XmlSigner();
        try {
            if (!xs.parseParams(args)) {
                System.exit(1);
                return;
            }
            xs.initialize(xs.providerClass, xs.providerType, xs.providerConfig, null, xs.pin);
            if (xs.infoOnly) {
                xs.printInfo();
                System.exit(0);
            }
            xs.signMetadata2();
            System.exit(0);
        } catch (ClassNotFoundException e) {
            System.err.println("Class not found: " + e.getMessage() + "\nTry to check value of \"providerclass\" in config file " + xs.cfgFile + ".");
            System.exit(2);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(3);
        }
    }
}
