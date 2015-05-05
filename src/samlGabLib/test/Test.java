package samlGabLib.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.AttributeValue;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.sun.org.apache.xml.internal.security.algorithms.SignatureAlgorithm;

public class Test {

	public Test() {

	}

	public static void main(String[] args) {

		/*
		 * SOAP11Encoder soapEncoder = new SOAP11Encoder();
		 * 
		 * MessageContext messageContext = null;
		 * soapEncoder.encode(messageContext);
		 */
		// http://www.programcreek.com/java-api-examples/index.php?api=org.opensaml.SAMLException
		// http://web-gmazza.rhcloud.com/blog/entry/opensaml-with-web-services
		try {
			DefaultBootstrap.bootstrap();
			AssertionBuilder ab = new AssertionBuilder();

			// Assertion.
			Assertion assertion = ab.buildObject();
			assertion.setVersion(SAMLVersion.VERSION_20);
			assertion.setID("_cb7f518664f2199119a3d09c9927de60");
			assertion.setIssueInstant(new DateTime());

			// Issuer
			IssuerBuilder ib = new IssuerBuilder();
			Issuer myIssuer = ib.buildObject();
			myIssuer.setValue("HC -");
			assertion.setIssuer(myIssuer);

			// Subject
			SubjectBuilder sb = new SubjectBuilder();
			Subject mySubject = sb.buildObject();
			NameIDBuilder nb = new NameIDBuilder();
			NameID myNameID = nb.buildObject();
			myNameID.setValue("CN=SAP, OU=Vegeu https://www.catcert.cat/verCDA-1 (c)03, OU=Serveis Públics de Certificació CDA-1, O=Consorci Sanitari Integral, C=ES");
			myNameID.setFormat(NameIdentifier.X509_SUBJECT);
			mySubject.setNameID(myNameID);
			assertion.setSubject(mySubject);

			ConditionsBuilder cb = new ConditionsBuilder();
			Conditions myConditions = cb.buildObject();
			// myConditions.setNotBefore("2015-03-16T12:32:26.024Z");

			// myConditions.setNotOnOrAfter("2015-03-16T12:41:06.024Z");
			myConditions.setNotBefore(new DateTime());
			myConditions.setNotOnOrAfter(new DateTime());

			AttributeStatementBuilder attstmtb = new AttributeStatementBuilder();
			AttributeStatement attstmt = attstmtb.buildObject();

			assertion.getAttributeStatements().add(
					newAttribute("ResponsibleUser", "HCC0126WS", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("PersonalUser", "9999999", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("GivenName", "A", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("FirstFamilyName", "B", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("SecondFamilyName", "C", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("DocumentType", "01", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("documentNumber", "12345678A", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("Code", "9999999", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("Profile", "MD", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("ProviderOrganization", "H08858656", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("Entity", "0126", attstmt));
			assertion.getAttributeStatements().add(
					newAttribute("CodeUP", "05994", attstmt));

			// Signature

			SignatureBuilder signb = new SignatureBuilder();
			SignatureImpl signature = signb.buildObject();
			// signature.setCanonicalizationAlgorithm("http://www.w3.org/2001/10/xml-exc-c14n#");
			signature
					.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			// XMLSignature xmlSignature = new XMLSignature(elementSignature,
			// "http://www.example.org");
			
			String xml = "<?xml version='1.0' encoding='UTF-8'?><Gabriel>yes</Gabriel>";
//			InputStream xmlInputStream = xmlString2InputStream(xml);
//			Document document = getXMLDocument(xmlInputStream);
			Document document = null;
			try {
				document = loadXMLFrom(xml);
			} catch (SAXException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (IOException e2) {
				// TODO Auto-generated catch block
				e2.printStackTrace();
			}
			
			String baseURI ="http://csi.org";
			SignatureAlgorithm.registerDefaultAlgorithms();
			
			/*
			try {
				//SignatureAlgorithm.register(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, "org.apache.xml.security.algorithms.implementations.SignatureBaseRSA.SignatureRSASHA1");
				//SignatureAlgorithm.register(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, SignatureRSASHA1.class);
				//SignatureRSASHA1 sigAlg = new SignatureRSASHA1();
				//SignatureAlgorithm.register(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1, sigAlg);
				
				
			} catch (AlgorithmAlreadyRegisteredException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (ClassNotFoundException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			} catch (XMLSignatureException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}*/
			
			
			XMLSignature xmlSignature =null;
			try {
				xmlSignature = new XMLSignature(
						document, 
						baseURI, 
						//"http://www.w3.org/2000/09/xmldsig#rsa-sha1"
						SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1
						);
				
			} catch (XMLSecurityException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
						
			//signature.setDOM(document.getDocumentElement());
			signature.setCanonicalizationAlgorithm(CanonicalizationMethod.EXCLUSIVE);
			signature.setXMLSignature(xmlSignature);
			assertion.setSignature(signature);

			// user authenticated via X509 token
			AuthnStatementBuilder asb = new AuthnStatementBuilder();
			AuthnStatement myAuthnStatement = asb.buildObject();
			myAuthnStatement.setAuthnInstant(new DateTime());
			AuthnContextBuilder acb = new AuthnContextBuilder();
			AuthnContext myACI = acb.buildObject();
			AuthnContextClassRefBuilder accrb = new AuthnContextClassRefBuilder();
			AuthnContextClassRef accr = accrb.buildObject();
			accr.setAuthnContextClassRef(AuthnContext.X509_AUTHN_CTX);
			myACI.setAuthnContextClassRef(accr);
			myAuthnStatement.setAuthnContext(myACI);
			assertion.getAuthnStatements().add(myAuthnStatement);

			/*
			 * // user has math degree AttributeStatementBuilder attstmtb = new
			 * AttributeStatementBuilder(); AttributeStatement attstmt =
			 * attstmtb.buildObject(); AttributeBuilder attbldr = new
			 * AttributeBuilder(); Attribute attr = attbldr.buildObject();
			 * attr.setName("degree");
			 * attr.setNameFormat("http://www.example.org/DoubleIt/Security");
			 * XSStringBuilder stringBuilder = (XSStringBuilder) Configuration
			 * .getBuilderFactory().getBuilder(XSString.TYPE_NAME); XSString
			 * stringValue = stringBuilder
			 * .buildObject(AttributeValue.DEFAULT_ELEMENT_NAME,
			 * XSString.TYPE_NAME); stringValue.setValue("Mathematics");
			 * attr.getAttributeValues().add(stringValue);
			 * attstmt.getAttributes().add(attr);
			 * assertion.getAttributeStatements().add(attstmt);
			 */

			// marshall Assertion Java class into XML
			MarshallerFactory marshallerFactory = Configuration
					.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
			Element assertionElement = marshaller.marshall(assertion);

			/*
			 * securityElement.appendChild(soapPart.importNode(
			 * assertionElement, true));
			 */

			Transformer transformer;
			try {

				transformer = TransformerFactory.newInstance().newTransformer();
				transformer.setOutputProperty(OutputKeys.INDENT, "yes");
				transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
						"yes");
				StreamResult result = new StreamResult(new StringWriter());
				DOMSource source = new DOMSource(
						assertionElement.getParentNode());

				transformer.transform(source, result);
				String xmlString = result.getWriter().toString();
				System.out.println(xmlString);

			} catch (TransformerConfigurationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (TransformerFactoryConfigurationError e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (TransformerException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			Element elemento = assertion.getDOM();
			int i = 0;

			// SOAPMessage message = smc.getMessage();
		} catch (ConfigurationException e) {
			e.printStackTrace();
		} catch (MarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static AttributeStatement newAttribute(String name, String value,
			AttributeStatement attstmt) {
		AttributeBuilder attbldr = new AttributeBuilder();
		Attribute attr = attbldr.buildObject();
		attr.setName(name);
		XSStringBuilder stringBuilder = (XSStringBuilder) Configuration
				.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
		XSString stringValue = stringBuilder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		stringValue.setValue(value);
		attr.getAttributeValues().add(stringValue);
		attstmt.getAttributes().add(attr);
		return attstmt;

	}

	private static InputStream xmlString2InputStream(String xml){
		
		InputStream inputStream=null;

			inputStream = new ByteArrayInputStream(xml.getBytes());

		return inputStream;
		
	}
	
	private static Document getXMLDocument(InputStream is) {
		Document doc = null;
		
		try {
			doc = loadXMLFrom(is);
		} catch (SAXException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return doc;
	}
	
	//@SuppressWarning("unused")
	private static org.w3c.dom.Document loadXMLFrom(String xml)
		    throws org.xml.sax.SAXException, java.io.IOException {
		
		
		//    return loadXMLFrom(new java.io.ByteArrayInputStream(xml.getBytes()));
		
	    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

	    factory.setNamespaceAware(true);
	    DocumentBuilder builder = null;
		try {
			builder = factory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	    return builder.parse(new ByteArrayInputStream(xml.getBytes()));
		}

	private static org.w3c.dom.Document loadXMLFrom(java.io.InputStream is) 
		    throws org.xml.sax.SAXException, java.io.IOException {
		    javax.xml.parsers.DocumentBuilderFactory factory =
		        javax.xml.parsers.DocumentBuilderFactory.newInstance();
		    factory.setNamespaceAware(true);
		    javax.xml.parsers.DocumentBuilder builder = null;
		    try {
		        builder = factory.newDocumentBuilder();
		    }
		    catch (javax.xml.parsers.ParserConfigurationException ex) {
		    }  
		    org.w3c.dom.Document doc = builder.parse(is);
		    is.close();
		    return doc;
		}

}
