package risalat;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import javax.xml.XMLConstants;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.SchemaFactory;

/**
 * 
 * @author yahya.yai (yahya.yai@nraa.gov.om)
 * copyright© National Records and Archives Authority, Sultanate of Oman
 *
 */
class XMLSchemaValidator {

	public static void main(String[] args) {
		try(InputStream xmlInputStream = new FileInputStream("root/header/meta.xml")) {
				SchemaFactory
					.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
					.newSchema(new File("root/header/meta.xsd"))
					.newValidator()
					.validate(new StreamSource(xmlInputStream));
				System.out.println("OK. No schema validation problems for meta.xml");
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		try(InputStream xmlInputStream = new FileInputStream("root/contents/toc.xml")) {
			SchemaFactory
				.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
				.newSchema(new File("root/contents/toc.xsd"))
				.newValidator()
				.validate(new StreamSource(xmlInputStream));
			System.out.println("OK. No schema validation problems for toc.xml");
		} catch(Exception e) {
			e.printStackTrace();
		}
	}
}
