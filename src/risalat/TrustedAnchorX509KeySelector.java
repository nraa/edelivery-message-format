package risalat;

import java.security.Key;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Iterator;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;

/**
 * 
 * @author yahya.yai [yahya.yai@nraa.gov.om]
 * copyright© National Records and Archives Authority, Sultanate of Oman
 *
 */
public class TrustedAnchorX509KeySelector extends KeySelector {
	private KeyStore ks;

	public TrustedAnchorX509KeySelector(KeyStore ks) {
		this.ks = ks;
	}

	@SuppressWarnings("rawtypes")
	public KeySelectorResult select(
			KeyInfo keyInfo, 
			KeySelector.Purpose purpose,
			AlgorithmMethod method,
			XMLCryptoContext context) throws KeySelectorException {
		Iterator ki = keyInfo.getContent().iterator();
		
		while (ki.hasNext()) {
			XMLStructure info = (XMLStructure) ki.next();
			if (!(info instanceof X509Data))
				continue;
			X509Data x509Data = (X509Data) info;
			Iterator xi = x509Data.getContent().iterator();
			
			while (xi.hasNext()) {
				Object o = xi.next();
				if (!(o instanceof X509Certificate))
					continue;
					
				X509Certificate cert = (X509Certificate) o;
				
				/*
				 * Not all signing certificates may contain a KeyUsage 
				 * element in it. But if it has, the KeyUsage bit for 
				 * digital signatures (bit 0) must be true. So skip those
				 * certificates which are not used for digital signatures.
				 */
				//Check that this is the certificate used for signing
				boolean[]  keyUsage = cert.getKeyUsage();
				if (keyUsage != null && keyUsage[0] == false) {
					continue;
				}
				
				// Check that the certificate from KeyInfo is a trusted certificate 
				// i.e. it exists in the trusted keystore or is part
				// of a trusted certificate chain
				if (!isTrustedCertificate(ks, cert)) {
					continue;
				}
				
				final PublicKey key = cert.getPublicKey();
				
				// Make sure the algorithm is compatible
				// with the method.
				if (algEquals(method.getAlgorithm(), key.getAlgorithm())) {
					return new KeySelectorResult() {
						public Key getKey() { return key; }
					};
				}
			}
		}
		
		throw new KeySelectorException("No key found!");
	}

	static boolean algEquals(String algURI, String algName) {
		if ((algName.equalsIgnoreCase("DSA") && algURI.equalsIgnoreCase(SignatureMethod.DSA_SHA1))
				|| (algName.equalsIgnoreCase("RSA") && algURI.equalsIgnoreCase(SignatureMethod.RSA_SHA1))) {
			return true;
		} else {
			return false;
		}
	}

	private boolean isTrustedCertificate(KeyStore ks, Certificate cert) {
		try {
			/* Check that the cert (the signature's certificate) is in the keystore.
			 * The method getCertificateAlias() compares given cert
			 * with either the certificate in a TrustedCertificateEntry
			 * or the first certificate in a certificate chain of a 
			 * PrivateKeyEntry.
			 */
			if (ks.getCertificateAlias(cert) != null) {
				return true;
			} else {
				/* Check that the cert is signed by an intermediate or
				 * root certificate in the keystore. These intermediate or
				 * root certificates may be found either in a TrustedCertificateEntry
				 * or in the certificate chain of a PrivateKeyEntry
				 */
				while(ks.aliases().hasMoreElements()) {
					String alias = ks.aliases().nextElement();
					if (ks.isCertificateEntry(alias)) {
						Certificate certificate = ks.getCertificate(alias);
						try {
							cert.verify(certificate.getPublicKey());
							return true;
						} catch (Exception e) {
							continue;
						}
					} else {
						Certificate[] certificates = ks.getCertificateChain(alias);
						if (certificates != null) {
							for (int i = 0; i < certificates.length; i++) {
								try {
									cert.verify(certificates[i].getPublicKey());
									return true;
								} catch (Exception e) {
									continue;
								}
							}
						}
					}
				}
			}
		} catch (Exception e) {
			return false;
		}
		
		return false;
	}
}
