package au.csiro.nt.pdsp.util;

import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelector.Purpose;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

public class X509KeySelector extends KeySelector {

    public KeySelectorResult select(KeyInfo keyInfo, KeySelector.Purpose purpose, AlgorithmMethod method, XMLCryptoContext context)
            throws KeySelectorException {
        Iterator ki = keyInfo.getContent().iterator();
        while (ki.hasNext()) {
            XMLStructure info = (XMLStructure) ki.next();
            if ((info instanceof X509Data)) {
                X509Data x509Data = (X509Data) info;
                Iterator xi = x509Data.getContent().iterator();
                while (xi.hasNext()) {
                    Object o = xi.next();
                    if ((o instanceof X509Certificate)) {
                        final PublicKey key = ((X509Certificate) o).getPublicKey();

                        if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
                            return new KeySelectorResult() {
                                public Key getKey() {
                                    return key;
                                }
                            };
                        }
                    }
                }
            }
        }
        throw new KeySelectorException("No key found!");
    }

    static boolean algEquals(String algURI, String algName) {
        if (((algName.equalsIgnoreCase("DSA")) && (algURI.equalsIgnoreCase("http://www.w3.org/2000/09/xmldsig#dsa-sha1"))) || ((algName.equalsIgnoreCase("RSA")) && (algURI.equalsIgnoreCase("http://www.w3.org/2000/09/xmldsig#rsa-sha1")))) {
            return true;
        }
        return false;
    }
}
