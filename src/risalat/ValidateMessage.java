package risalat;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.codec.digest.DigestUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Takes a signed XML document (enveloped XML Digital Signature) and 
 * validates its signature.
 * 
 * @author yahya.yai [yahya.yai@nraa.gov.om]
 * copyright© National Records and Archives Authority, Sultanate of Oman
 *
 */
public class ValidateMessage {
	private static final String KEY_STORE_PATH = "keystore.jks";
    private static final String KEY_STORE_PASS = "p@ssw0rd";
    private static final String KEY_STORE_TYPE = "PKCS12";
    private static final String PATH_TO_XML = "root/header/meta.xml";
    
	@SuppressWarnings("unchecked")
	public static void main(String[] args) {
		System.out.println("Validating enveloped XML Digital Signature.");

		try {
			/*
			 * Load keystore and get signing key and certificate by its alias
			 */
			final KeyStore keyStore = loadKeyStore(new File(KEY_STORE_PATH));
			
	        /*
	         * Load the signed (enveloped) XML document to be validated
	         */
	        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
	        dbf.setNamespaceAware(true);
	        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(PATH_TO_XML));
	        
	        /*
	         * Get the Signature element within the XML document
	         */
	        NodeList nodeList = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
	        if (nodeList.getLength() == 0) {
	        	throw new Exception("The XML document does not have a digital signature");
	        }
	        
	        /*
	         * Create a DOMValidateContext and specify a KeySelector and document context
	         */
	        DOMValidateContext vc = new DOMValidateContext(
	        		new TrustedAnchorX509KeySelector(keyStore), nodeList.item(0));
	        		//new X509KeySelector(keyStore), nodeList.item(0));
	        vc.setProperty("javax.xml.crypto.dsig.cacheReference", true);
	        
	        /*
	         * Unmarshall the XMLSignature
	         */
	        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
	        XMLSignature signature = fac.unmarshalXMLSignature(vc);
	        
	        /*
	         * Validate the XMLSignature
	         */
	        boolean coreValidity = signature.validate(vc);
	        
	        if (!coreValidity) {
	        	System.err.println("Signature failed core validation");
	        	boolean sv = signature.getSignatureValue().validate(vc);
	        	System.err.println(String.format("signature validation status: %s", sv));
	        	if (!sv) {
	        		int index = 0;
	        		for (Object o : signature.getSignedInfo().getReferences()) {
	        			Reference r = (Reference) o;
	        			boolean refValid = false;
	        			try {
							refValid = ((Reference) r).validate(vc);
						} catch (XMLSignatureException e) {
							e.printStackTrace();
						}
	        			System.err.println(String.format("ref[%d] validity status: %s", index, refValid));
	        			index++;
	        		}
	        	}
	        	throw new Exception("Signature failed core validation");
	        } else {
	        	System.out.println("Signature passed core validation");
	        }
	        
	        /*
	         * TODO: validate digest of toc.xml
	         */
	        XPathFactory xpf = XPathFactory.newInstance();
	        XPath xpath = xpf.newXPath();
	        
	        String tocDigestAlgo = (String) xpath.evaluate("/message/toc/digest-algo/text()", doc, XPathConstants.STRING);
	        String tocDigestValue = (String) xpath.evaluate("/message/toc/digest-value/text()", doc, XPathConstants.STRING);
	        String digest = new DigestUtils(tocDigestAlgo).digestAsHex(new File("root/contents/toc.xml"));
	        
	        if (!tocDigestValue.equals(digest)) {
	        	throw new Exception("toc.xml failed validation checks");
	        } else {
	        	System.out.println("toc.xml passed validation checks");
	        }
	        
	        
	        /*
	         * The following validates digests of every file mentioned in toc.xml
	         */
	        Document docToc = dbf.newDocumentBuilder().parse(new FileInputStream("root/contents/toc.xml"));
	        
	        /*
	         * Validate the message digest of the body element of toc.xml
	         */
	        String fileRef = (String) xpath.evaluate("/toc/body/@fileref", docToc, XPathConstants.STRING);
	        String bodyDigestAlgo = (String) xpath.evaluate("/toc/body/digest-algo/text()", docToc, XPathConstants.STRING);
	        String bodyDigestValue = (String) xpath.evaluate("/toc/body/digest-value/text()", docToc, XPathConstants.STRING);
	        digest = new DigestUtils(bodyDigestAlgo).digestAsHex(new File("root/contents/" + fileRef));
	        
	        if (!bodyDigestValue.equals(digest)) {
	        	throw new Exception(fileRef + " failed validation checks");
	        } else {
	        	System.out.println(fileRef + " passed validation checks");
	        }
	        
	        /*
	         * Validate the message digest of each attachment element of toc.xml
	         */
	        NodeList attachments = (NodeList) xpath.evaluate("/toc/attachment-list/attachment", docToc, XPathConstants.NODESET);
	        for (int i = 0; i < attachments.getLength(); i++) {
	        	Node attachment = attachments.item(i);
	        	fileRef = (String) xpath.evaluate("@fileref", attachment, XPathConstants.STRING);
	        	String attachmentDigestAlgo = (String) xpath.evaluate("digest-algo/text()", attachment, XPathConstants.STRING);
	        	String attachmentDigestValue = (String) xpath.evaluate("digest-value/text()", attachment, XPathConstants.STRING);
	        	digest = new DigestUtils(attachmentDigestAlgo).digestAsHex(new File("root/contents/" + fileRef));
	        	
	        	if (!attachmentDigestValue.equals(digest)) {
		        	throw new Exception(fileRef + " failed validation checks");
		        } else {
		        	System.out.println(fileRef + " passed validation checks");
		        }
	        }
	        
	        /*
	         * Validate that no extra files are added to contents folder that is not listed in toc.xml
	         * The contents files will contain the toc.xml, toc.xsd, the body file, and the attachment files.
	         */
	        int numFiles = 3 + attachments.getLength();
	        File contents = new File("root/contents");
	        if (contents.listFiles().length != numFiles) {
	        	throw new Exception("Extraneous attachments found in message envelope!");
	        }
	        
	        System.out.println("Full validation checks completed successfully");
	        		
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
