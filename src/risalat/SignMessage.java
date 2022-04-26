package risalat;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;

/**
 * Takes an XML document and uses keys in an existing keystore to sign 
 * the XML document and embed the signature information into the XML 
 * document itself (i.e. enveloped XML Digital Signature).
 * @author yahya.yai [yahya.yai@nraa.gov.om]
 * copyright© National Records and Archives Authority, Sultanate of Oman
 */
public class SignMessage {
	private static final String KEY_STORE_PATH = "keystore.jks";
	private static final String PRIVATE_KEY_ALIAS = "hugoboss";
    private static final String PRIVATE_KEY_PASS = "p@ssw0rd";
    private static final String KEY_STORE_PASS = "p@ssw0rd";
    private static final String KEY_STORE_TYPE = "PKCS12";
    private static final String PATH_TO_XML = "root/header/meta.xml";
    
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public static void main(String[] args) {
		System.out.println("Generating enveloped XML Digital Signature.");

		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

		try {
			/*
			 * Create the Reference object which identifies data that will be digested and
			 * signed.
			 */
			DigestMethod digestMethod = fac.newDigestMethod(DigestMethod.SHA256, null);
			Transform transform = fac.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
			Reference ref = fac.newReference("", digestMethod, Collections.singletonList(transform), null, null);
			
			/*
			 * Create SignedInfo
			 */
			CanonicalizationMethod cm = fac.newCanonicalizationMethod(
					CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS, (C14NMethodParameterSpec) null);
			SignatureMethod sm = fac.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
			SignedInfo si = fac.newSignedInfo(cm, sm, Collections.singletonList(ref));
			
			/*
			 * Load keystore and get signing key and certificate by its alias
			 */
			final KeyStore keyStore = loadKeyStore(new File(KEY_STORE_PATH));
			final Key privateKey = keyStore.getKey(PRIVATE_KEY_ALIAS, PRIVATE_KEY_PASS.toCharArray());
	        final X509Certificate cert = (X509Certificate) keyStore.getCertificate(PRIVATE_KEY_ALIAS);
	        
	        /*
	         * Create KeyInfo containing X509Data
	         */
	        KeyInfoFactory kif = fac.getKeyInfoFactory();
	        List x509Content = new ArrayList();
	        x509Content.add(cert.getSubjectX500Principal().getName());
	        x509Content.add(cert);
	        X509Data xd = kif.newX509Data(x509Content);
	        KeyInfo ki = kif.newKeyInfo(Collections.singletonList(xd));
	        
	        /*
	         * Instantiate the XML document to be signed
	         */
	        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	        dbf.setNamespaceAware(true);
	        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(PATH_TO_XML));
	        
	        /*
	         * Create the DOMSignContext and specify RSA private key and location of the
	         * resulting XMLSignature's parent element
	         */
	        DOMSignContext dsc = new DOMSignContext(privateKey, doc.getDocumentElement());
	        
	        /*
	         * Create the XMLSignature, but don't sign it yet
	         */
	        XMLSignature signature = fac.newXMLSignature(si, ki);
	        
	        /*
	         * Marshall, generate, and sign the enveloped signature
	         */
	        signature.sign(dsc);
	        
	        /*
	         * Output the resulting document to the same file
	         */
	        OutputStream os = new FileOutputStream(PATH_TO_XML);
	        TransformerFactory tf = TransformerFactory.newInstance();
	        Transformer trans = tf.newTransformer();
	        trans.transform(new DOMSource(doc), new StreamResult(os));
	        
	        System.out.println("Finished signing document");
	        		
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static KeyStore loadKeyStore(File privateKeyFile) throws Exception {
        final InputStream fileInputStream = new FileInputStream(privateKeyFile);
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
            keyStore.load(fileInputStream, KEY_STORE_PASS.toCharArray());
            return keyStore;
        }
        finally {
            fileInputStream.close();
        }
    }

}
