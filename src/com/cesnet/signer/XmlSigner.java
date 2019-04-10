package com.cesnet.signer;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Provider.Service;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.util.*;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.Init;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.reference.ReferenceData;
import org.apache.xml.security.signature.reference.ReferenceSubTreeData;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.transforms.TransformationException;
import org.apache.xml.security.transforms.Transforms;

import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class XmlSigner {
    private static final String SHA1_DIGEST   = "http://www.w3.org/2000/09/xmldsig#sha1";
    private static final String SHA1_METHOD   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
    private static final String SHA256_DIGEST = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String SHA256_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
    private static final String SHA512_DIGEST = "http://www.w3.org/2001/04/xmlenc#sha512";
    private static final String SHA512_METHOD = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    private KeyStore keyStore;
    private String keyStoreType;
    private String keyStoreProvider;
    private String keyStoreFileName;
    private char[] password;
    private String inputFile = null;
    private String outputFile = null;
    private String cfgFile = null;
    private String digestMethod = SHA256_DIGEST;
    private String signatureMethod = SHA256_METHOD;
    private String signingAlias = null;
    private boolean infoOnly = false;

    private static String signaturePosition = "FIRST";

    private static Logger logger = LoggerFactory.getLogger(XmlSigner.class);

    private static Element getSignatureElement(Document xmlDoc) {
        logger.trace("getSignatureElement <");
        List sigElements = XMLHelper.getChildElementsByTagNameNS(xmlDoc.getDocumentElement(), Signature.DEFAULT_ELEMENT_NAME.getNamespaceURI(), Signature.DEFAULT_ELEMENT_NAME.getLocalPart());
        if (sigElements.isEmpty()) {
            logger.trace("getSignatureElement >");
            return null;
        } else {
            if (sigElements.size() > 1) {
                logger.error("XML document contained more than one signature, unable to process, exiting");
                System.exit(7);
            }
            logger.trace("getSignatureElement >");
            return (Element)sigElements.get(0);
        }
    }

    private static String getSignatureReferenceUri(String referenceIdAttributeName, Element rootElement) {
        logger.trace("getSignatureReferenceUri <");
        String reference = "";
        if (referenceIdAttributeName != null) {
            Attr referenceAttribute = (Attr)rootElement.getAttributes().getNamedItem(referenceIdAttributeName);
            if (referenceAttribute != null) {
                rootElement.setIdAttributeNode(referenceAttribute, true);
                reference = DatatypeHelper.safeTrim(referenceAttribute.getValue());
                if (reference.length() > 0) {
                    reference = "#" + reference;
                }
            }
        }
        logger.trace("getSignatureReferenceUri >");
        return reference;
    }

    private static void addSignatureELement(String position, Element root, Element signature) {
        logger.trace("addSignatureELement <");
        switch(position) {
            case "FIRST":
                root.insertBefore(signature, root.getFirstChild());
                break;

            case "LAST":
                root.appendChild(signature);
                break;
        }
    }

    private static void markIdAttribute(Element docElement, Reference reference) {
        logger.trace("markIdAttribute <");
        String referenceUri = reference.getURI();
        if (!DatatypeHelper.isEmpty(referenceUri)) {
            if (XMLHelper.getIdAttribute(docElement) == null) {
                if (!referenceUri.startsWith("#")) {
                    logger.error("Signature Reference URI was not a document fragment reference: " + referenceUri);
                    System.exit(100);
                }

                String id = referenceUri.substring(1);
                NamedNodeMap attributes = docElement.getAttributes();

                for(int i = 0; i < attributes.getLength(); ++i) {
                    Attr attribute = (Attr)attributes.item(i);
                    if (id.equals(attribute.getValue())) {
                        docElement.setIdAttributeNode(attribute, true);
                        logger.trace("markIdAttribute >");
                        return;
                    }
                }

            }
        }
    }

    private static Reference extractReference(XMLSignature signature) {
        logger.trace("extractReference <");
        int numReferences = signature.getSignedInfo().getLength();
        if (numReferences != 1) {
            logger.error("Signature SignedInfo had invalid number of References: " + numReferences);
            System.exit(101);
        }

        Reference ref = null;

        try {
            ref = signature.getSignedInfo().item(0);
        } catch (XMLSecurityException e) {
            logger.error("Apache XML Security exception obtaining Reference" + e);
            System.exit(102);
        }

        if (ref == null) {
            logger.error("Signature Reference was null");
            System.exit(103);
        }

        return ref;
    }

    private static void validateSignatureReferenceUri(Document xmlDocument, Reference reference) {
        logger.trace("validateSignatureReferenceUri <");
        ReferenceData refData = reference.getReferenceData();
        if (refData instanceof ReferenceSubTreeData) {
            ReferenceSubTreeData subTree = (ReferenceSubTreeData)refData;
            Node root = subTree.getRoot();
            Node resolvedSignedNode = root;
            if (root.getNodeType() == 9) {
                resolvedSignedNode = ((Document)root).getDocumentElement();
            }

            Element expectedSignedNode = xmlDocument.getDocumentElement();
            if (!expectedSignedNode.isSameNode(resolvedSignedNode)) {
                logger.error("Signature Reference URI \"" + reference.getURI() + "\" was resolved to a node other than the document element");
                System.exit(200);
            }
        } else {
            logger.error("Signature Reference URI did not resolve to a subtree");
            System.exit(201);
        }

    }

    private static void validateSignatureTransforms(Reference reference) {
        logger.trace("validateSignatureTransforms <");
        Transforms transforms = null;

        try {
            transforms = reference.getTransforms();
        } catch (XMLSecurityException e) {
            logger.error("Apache XML Security error obtaining Transforms instance: " + e.getMessage());
            System.exit(202);
        }

        if (transforms == null) {
            logger.error("Error obtaining Transforms instance, null was returned");
            System.exit(203);
        }

        int numTransforms = transforms.getLength();
        if (numTransforms > 2) {
            logger.error("Invalid number of Transforms was present: " + numTransforms);
            System.exit(204);
        }

        boolean sawEnveloped = false;

        for(int i = 0; i < numTransforms; ++i) {
            Transform transform = null;

            try {
                transform = transforms.item(i);
            } catch (TransformationException var7) {
                logger.error("Error obtaining transform instance");
                System.exit(200);
            }

            String uri = transform.getURI();
            if ("http://www.w3.org/2000/09/xmldsig#enveloped-signature".equals(uri)) {
                logger.error("Saw Enveloped signature transform");
                sawEnveloped = true;
            } else if (!"http://www.w3.org/2001/10/xml-exc-c14n#".equals(uri) && !"http://www.w3.org/2001/10/xml-exc-c14n#WithComments".equals(uri)) {
                logger.error("Saw invalid signature transform: " + uri);
                System.exit(200);
            } else {
                logger.error("Saw Exclusive C14N signature transform");
            }
        }

        if (!sawEnveloped) {
            logger.error("Signature was missing the required Enveloped signature transform");
            System.exit(200);
        }

    }

    private static void validateSignatureReference(Document xmlDocument, Reference ref) {
        validateSignatureReferenceUri(xmlDocument, ref);
        validateSignatureTransforms(ref);
    }

    private static void populateKeyInfo(Document doc, KeyInfo keyInfo, Certificate crt) {
        logger.trace("populateKeyInfo <");
        try {
            PublicKey pk = crt.getPublicKey();
            keyInfo.add(pk);
            X509Data x509Data = new X509Data(doc);
            keyInfo.add(x509Data);
            X509Certificate xc = (X509Certificate)crt;
            x509Data.addCertificate(xc);
        } catch (XMLSecurityException var7) {
            logger.error("Cannot add KeyInfo");
            System.exit(30);
        }

    }

    private boolean signXmlFile(String signer, String xmlInFile, String xmlOutFile) throws Exception {
        logger.trace("signXmlFile <");
        if (signer == null) {
            logger.error("Missing signer");
            System.exit(3);
        }

        PrivateKey signerKey = (PrivateKey)this.keyStore.getKey(signer, this.password);
        if (signerKey == null) {
            logger.error("No such signer: " + signer);
            System.exit(4);
        }

        Certificate crt = this.keyStore.getCertificate(signer);
        PublicKey pubKey = crt.getPublicKey();
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = null;

        try {
            doc = dbf.newDocumentBuilder().parse(new FileInputStream(xmlInFile));
        } catch (IOException e) {
            logger.error("Cannot open input file " + xmlInFile);
            System.exit(5);
        }

        Element documentRoot = doc.getDocumentElement();
        Element signatureElement = getSignatureElement(doc);
        if (signatureElement != null) {
            logger.error("XML document is already signed");
            System.exit(8);
        }

        String c14nAlgorithm = "http://www.w3.org/2001/10/xml-exc-c14n#";

        try {
            XMLSignature signature = new XMLSignature(doc, "#", this.signatureMethod, c14nAlgorithm);
            Transforms contentTransforms = new Transforms(doc);
            contentTransforms.addTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
            contentTransforms.addTransform("http://www.w3.org/2001/10/xml-exc-c14n#");
            signature.addDocument(getSignatureReferenceUri("ID", documentRoot), contentTransforms, this.digestMethod);
            signatureElement = signature.getElement();
            addSignatureELement(signaturePosition, documentRoot, signatureElement);
            signature.sign(signerKey);
            populateKeyInfo(doc, signature.getKeyInfo(), crt);
            signatureElement = getSignatureElement(doc);
            if (signatureElement == null) {
                logger.error("Signature validation: document is not signed");
                System.exit(10);
            }

            signature = null;

            try {
                signature = new XMLSignature(signatureElement, "");
            } catch (XMLSecurityException e) {
                logger.error("Unable to read XML signature: " + e);
                System.exit(11);
            }

            if (signature.getObjectLength() != 0) {
                logger.error("Signature contained an Object element, this is not allowed");
                System.exit(12);
            }

            Reference ref = extractReference(signature);
            markIdAttribute(doc.getDocumentElement(), ref);
            if (!signature.checkSignatureValue(pubKey)) {
                logger.error("XML document signature verification failed");
                System.exit(91);
            }

            TransformerFactory tfac = TransformerFactory.newInstance();
            Transformer serializer = tfac.newTransformer();
            OutputStream os = new FileOutputStream(xmlOutFile);
            serializer.setOutputProperty("encoding", "UTF-8");
            serializer.transform(new DOMSource(doc), new StreamResult(os));
            return true;
        } catch (XMLSecurityException e) {
            logger.error("Unable to create XML document signature, " + e.toString());
            System.exit(9);
            return false;
        }
    }

    private void initialize(String storeFileName, char[] password) throws Exception {
        logger.trace("initialize <");
        System.setProperty("protect", "cardset");
        FileInputStream storeStream = new FileInputStream(storeFileName);
        keyStore = KeyStore.getInstance(keyStoreType, keyStoreProvider);
        keyStore.load(storeStream, password);
        Init.init();

    }

    private void printInfo() throws KeyStoreException {
        logger.trace("printInfo <");
        Provider[] providers = Security.getProviders();
        System.out.println("Provider list (" + providers.length + " providers found):\n");

        for(Provider p: providers) {
            System.out.println("    " + p.getName() + " (ver. " + p.getVersion() + ") - " + p.size() + " entries\n");
            Set services = p.getServices();
            Iterator it = services.iterator();
            System.out.println("        Services:");

            while(it.hasNext()) {
                Service ps = (Service)it.next();
                System.out.println("            " + ps.getType() + " - " + ps.getAlgorithm() + " - " + ps.getClassName());
            }

            System.out.println();
            System.out.println("        Setup:");
            Enumeration keys = p.keys();

            while(keys.hasMoreElements()) {
                Object key = keys.nextElement();
                Object value = p.get(key);
                System.out.println("            " + key.toString() + " = " + value.toString());
            }

            System.out.println();
        }

        System.out.println("Entries in keystore: " + this.keyStore.size());
        System.out.println("Provider name: " + this.keyStore.getProvider().getName());
        System.out.println("Provider type: " + this.keyStore.getType() + "\n");
        Enumeration aliases = this.keyStore.aliases();

        while(aliases.hasMoreElements()) {
            String alias = (String)aliases.nextElement();
            if (this.keyStore.isCertificateEntry(alias)) {
                Certificate cert = this.keyStore.getCertificate(alias);
                System.out.println("Alias (certificate): " + alias + "\nCert: " + cert.toString() + "\n");
            } else if (this.keyStore.isKeyEntry(alias)) {
                System.out.println("Alias (key): " + alias + "\n");
            } else {
                Certificate[] certChain = this.keyStore.getCertificateChain(alias);
                System.out.println("Alias (unknown type): " + alias);
                for(Certificate cert: certChain) {
                    System.out.println("Cert: " + cert.toString() + "\n\n");
                }
            }
        }

    }


    private void signMetadata() throws Exception {
        if (!this.signXmlFile(this.signingAlias, this.inputFile, this.outputFile)) {
            logger.error("Xml file was signed, but validation failed. Please contact support at support@cesnet.cz");
            System.exit(4);
        }
    }

    private void printUsage() {
        StringBuilder sb = new StringBuilder();
        sb.append("CESNET Metadata Signer v. 2\n\n");
        sb.append("Usage: XmlSigner -h\n");
        sb.append("           prints this help\n");
        sb.append("       XmlSigner -i <input_file.xml> -o <output_file.xml> -cfg <cfg_file> [-alg <sha256|sha1|sha512>] [-position <first|last|n>]\n");
        sb.append("           signs and verifies metadata\n");
        sb.append("           -i file to sign\n");
        sb.append("           -o signed file name\n");
        sb.append("           -cfg configuration file\n");
        sb.append("           -alg signature algorithm (default is sha256)\n");
        sb.append("           -position signature position in signed xml file. First - as first\n");
        sb.append("               element, last - as last element, n - as nth element (default is first)\n");
        sb.append("       XmlSigner -info <cfg_file>\n");
        sb.append("           prints keystore info\n");
        sb.append("\n");
        sb.append("  Sample cfg_file while using nCipher HSM:\n");
        sb.append("      keystore = my_store.jks\n");
        sb.append("      keystoretype = nCipher.sworld\n");
        sb.append("      keystoreprovider = nCipherKM\n");
        sb.append("      password = mysecretpassword\n");
        sb.append("      signingalias = key_alias\n");
        sb.append("\n");
        sb.append("Return value:\n");
        sb.append("    0 - OK, document was signed and verified.\n");
        sb.append("    >0 - An error occured.\n");
        System.out.println(sb.toString());
    }

    private boolean parseParams(String[] args) throws Exception {

        if (args.length == 0) {
            this.printUsage();
            return false;
        } else if (args.length == 1) {
            if (args[0].equals("-h")) {
                this.printUsage();
                return false;
            } else {
                System.out.println("Unknown parameter: " + args[0]);
                this.printUsage();
                return false;
            }
        } else if (args.length % 2 == 1) {
            System.out.println("Wrong parameter usage.");
            this.printUsage();
            return false;
        } else if (args.length == 2) {
            if (args[0].equals("-info")) {
                this.cfgFile = args[1];

                try {
                    if (!this.loadIniParams(this.cfgFile)) {
                        System.exit(1);
                    }
                } catch (FileNotFoundException var10) {
                    System.err.println("Error: Cannot find configuration file " + this.cfgFile);
                    System.exit(1);
                }

                this.infoOnly = true;
                return true;
            } else {
                System.out.println("Unknown parameter: " + args[1]);
                this.printUsage();
                return false;
            }
        } else {
            boolean iparam = false;
            boolean oparam = false;
            boolean cfgparam = false;

            for(int i = 0; i < args.length; ++i) {
                if (args[i].equals("-i")) {
                    iparam = true;
                    this.inputFile = args[++i];
                } else if (args[i].equals("-o")) {
                    oparam = true;
                    this.outputFile = args[++i];
                } else if (args[i].equals("-cfg")) {
                    cfgparam = true;
                    this.cfgFile = args[++i];
                } else {
                    if (args[i].equals("-alg")) {
                        String alg = args[++i];
                        switch(alg.toLowerCase()) {
                            case "sha1":
                                this.digestMethod = SHA1_DIGEST;
                                this.signatureMethod = SHA1_METHOD;
                                break;
                            case "sha512":
                                this.digestMethod = SHA512_DIGEST;
                                this.signatureMethod = SHA512_METHOD;
                                break;
                            case "sha256":
                                // Default value, do nothing
                                break;
                             default:
                                 // Unknown method
                                 System.err.println("Unknown digest method " + alg);
                                 System.exit(7);
                                 break;
                        }

                    } else if (args[i].equals("-position")) {
                        signaturePosition = args[++i];
                    } else {
                        System.err.println("Unknown parameter " + args[i] + " was ignored.");
                    }
                }
            }

            if (iparam && oparam && cfgparam) {
                this.loadIniParams(this.cfgFile);
                return true;
            } else {
                System.out.println("Wrong parameter usage.");
                this.printUsage();
                return false;
            }
        }
    }

    /**
     * @param iniFileName
     * @return
     * @throws Exception
     */
    private boolean loadIniParams(String iniFileName) throws Exception {
        Properties p = new Properties();
        p.load(new FileInputStream(iniFileName));

        this.keyStoreFileName = p.getProperty("keystore");
        if(this.keyStoreFileName == null) {
            logger.error("Error: Cannot find key \"keystore\" in config file.\n");
            return false;
        }

        this.keyStoreType = p.getProperty("keystoretype");
        if(this.keyStoreType == null) {
            logger.error("Error: Cannot find key \"keystoretype\" in config file.\n");
            return false;
        }

        this.keyStoreProvider = p.getProperty("keystoreprovider");
        if(this.keyStoreProvider == null) {
            logger.error("Error: Cannot find key \"keystoreprovider\" in config file.\n");
            return false;
        }

        String pwd = p.getProperty("password");
        if(pwd == null) {
            logger.error("Error: Cannot find key \"password\" in config file.\n");
            return false;
        }
        this.password = pwd.toCharArray();

        this.signingAlias = p.getProperty("signingalias");
        if(this.signingAlias == null) {
            logger.error("Error: Cannot find key \"signingalias\" in config file.\n");
            return false;
        }

        return true;
    }

    public static void main(String[] args) {

        logger.trace("main <");

        logger.info(logger.getClass().getName());

        XmlSigner signer = new XmlSigner();
        try {
            if (!signer.parseParams(args)) {
                System.exit(1);
            }
            signer.initialize(signer.keyStoreFileName, signer.password);
            if (signer.infoOnly) {
                signer.printInfo();
                System.exit(0);
            }
            signer.signMetadata();
            System.exit(0);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(100);
        }
    }
}
