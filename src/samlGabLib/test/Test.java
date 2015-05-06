package samlGabLib.test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
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
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

public class Test {

	// public final static String PKCS12_RESOURCE =
	// "./keystore/myKeystore.pkcs12";
	// public final static String PKCS12_RESOURCE = "./keystore/hc3.pkcs12";
	public final static String PKCS12_RESOURCE = "csiKeyStore.pkcs12";

	/**
	 * <p>
	 * Constraseña de acceso a la clave privada del usuario
	 * </p>
	 */
	// public final static String PKCS12_PASSWORD = "facturae";
	public final static String PKCS12_PASSWORD = "5n9eDmVM";// hc3

	public Test() {

	}

	private static Assertion buildAssertion() {
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
		return assertion;
	}

	private static void printResult(Element assertionElement) {
		Transformer transformer;
		try {

			transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
					"yes");
			StreamResult result = new StreamResult(new StringWriter());
			DOMSource source = new DOMSource(assertionElement.getParentNode());

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
	}

	public static void main(String[] args) {

		// https://narendrakadali.wordpress.com/2011/06/05/sign-assertion-using-opensaml/

		// http://mylifewithjava.blogspot.com.es/2012/11/signing-with-opensaml.html

		// https://narendrakadali.wordpress.com/2011/06/05/sign-assertion-using-opensaml/

		// http://blog.keksrolle.de/2010/07/27/how-to-create-a-valid-saml-2-0-assertion-with-opensaml-for-java.html

		// http://www.programcreek.com/java-api-examples/index.php?api=org.opensaml.SAMLException
		// http://web-gmazza.rhcloud.com/blog/entry/opensaml-with-web-services
		try {
			DefaultBootstrap.bootstrap();
			SignatureAlgorithm.registerDefaultAlgorithms();

			Assertion assertion = buildAssertion();

			// Signature
			/*
			 * SignatureBuilder signb = new SignatureBuilder(); SignatureImpl
			 * signature = signb.buildObject();
			 */

			Signature signature = (Signature) Configuration.getBuilderFactory()
					.getBuilder(Signature.DEFAULT_ELEMENT_NAME)
					.buildObject(Signature.DEFAULT_ELEMENT_NAME);

			signature
					.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
			signature
					.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
			
			
			
/*
			String xml = "<?xml version='1.0' encoding='UTF-8'?><Gabriel>yes</Gabriel>";
			Document document = null;
			try {
				document = loadXMLFrom(xml);
			} catch (SAXException e2) { // TODO Auto-generated catch block
				e2.printStackTrace();
			} catch (IOException e2) { // TODO Auto-generated catch block
										// e2.printStackTrace();
			}

			String baseURI ="";
			  XMLSignature xmlSignature =null; try { xmlSignature = new
			  XMLSignature( document, baseURI,
			  //"http://www.w3.org/2000/09/xmldsig#rsa-sha1"
			  SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1 );
			  //appendChild(xmlSignature.getElement());
			  
			  } catch (XMLSecurityException e1) { // TODO Auto-generated catch block 
				  e1.printStackTrace(); }
			  }
			  
			  signature.setXMLSignature(xmlSignature);
*/
			/*
			 * Prueba
			 */
			// https://svn.apache.org/repos/asf/santuario/xml-security-java/trunk/samples/org/apache/xml/security/samples/signature/CreateSignature.java
			X509Certificate cert = (X509Certificate) new Test()
					.getCertificate("csi");
			PrivateKey prKey = new Test().getPrivateKey("csi");

			BasicX509Credential credential = new BasicX509Credential();
			credential.setEntityCertificate(cert);
			credential.setPrivateKey(prKey);
			Credential signingCredential = credential;

			/*
			 * try { xmlSignature.addKeyInfo(cert); } catch
			 * (XMLSecurityException e1) { // TODO Auto-generated catch block
			 * e1.printStackTrace(); }
			 */
			signature.setSigningCredential(signingCredential);
			/*
			 * Transforms transforms=new Transforms(document); try {
			 * transforms.addTransform
			 * (Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
			 * transforms.addTransform
			 * (Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
			 * //xmlSignature.addDocument
			 * ("",transforms,org.apache.xml.security.utils
			 * .Constants.ALGO_ID_DIGEST_SHA1); xmlSignature.addDocument("",
			 * transforms,
			 * org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1); }
			 * catch (TransformationException e1) { // TODO Auto-generated catch
			 * block e1.printStackTrace(); } catch (XMLSignatureException e) {
			 * // TODO Auto-generated catch block e.printStackTrace(); } try {
			 * xmlSignature.sign(prKey); } catch (XMLSignatureException e1) { //
			 * TODO Auto-generated catch block e1.printStackTrace(); }
			 * 
			 * try { xmlSignature.addKeyInfo(cert); } catch
			 * (XMLSecurityException e1) { // TODO Auto-generated catch block
			 * e1.printStackTrace(); }
			 */

			// gabriel
			/*
			 * try {
			 * 
			 * 
			 * KeyInfo
			 * keyInfo=(KeyInfo)buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
			 * X509Data
			 * data=(X509Data)buildXMLObject(X509Data.DEFAULT_ELEMENT_NAME);
			 * X509Certificate
			 * cert=(X509Certificate)buildXMLObject(X509Certificate
			 * .DEFAULT_ELEMENT_NAME); String
			 * value=org.apache.xml.security.utils
			 * .Base64.encode(cred.getEntityCertificate().getEncoded());
			 * cert.setValue(value); data.getX509Certificates().add(cert);
			 * keyInfo.getX509Datas().add(data); signature.setKeyInfo(keyInfo);
			 * } catch ( CertificateEncodingException e) { throw new
			 * SAML2SSOUIAuthenticatorException("errorGettingCert"); }
			 */

			// \gabriel
			// KeyInfo keyInfo = null;
			/*
			 * SecurityConfiguration secConfiguration =
			 * Configuration.getGlobalSecurityConfiguration();
			 * NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager =
			 * secConfiguration.getKeyInfoGeneratorManager();
			 * KeyInfoGeneratorManager keyInfoGeneratorManager =
			 * namedKeyInfoGeneratorManager.getDefaultManager();
			 * KeyInfoGeneratorFactory keyInfoGeneratorFactory =
			 * keyInfoGeneratorManager.getFactory(signingCredential);
			 * KeyInfoGenerator keyInfoGenerator =
			 * keyInfoGeneratorFactory.newInstance();
			 * 
			 * 
			 * try { keyInfo = keyInfoGenerator.generate(signingCredential); }
			 * catch (Exception e) { e.printStackTrace(); }
			 * 
			 * signature.setKeyInfo(keyInfo);
			 */
			/*
			 * KeyInfoBuilder kib = new KeyInfoBuilder().buildObject(null);
			 * KeyInfo keyInfo = new KeyInfo(KeyInfo.DEFAULT_ELEMENT_NAME);
			 * 
			 * signature.setKeyInfo(null); assertion.setSignature(signature);
			 */
			MarshallerFactory marshallerFactory = Configuration
					.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
			Element assertionElement = marshaller.marshall(assertion);

			XMLSignature xmlSignature = ((SignatureImpl)signature).getXMLSignature();
			try {
				Signer.signObject(signature);
			} catch (SignatureException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			/*
			 * Fin prueba
			 */

			// marshall Assertion Java class into XML

			printResult(assertionElement);

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

	private static InputStream xmlString2InputStream(String xml) {

		InputStream inputStream = null;

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

	// @SuppressWarning("unused")
	private static org.w3c.dom.Document loadXMLFrom(String xml)
			throws org.xml.sax.SAXException, java.io.IOException {

		// return loadXMLFrom(new java.io.ByteArrayInputStream(xml.getBytes()));

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
		javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory
				.newInstance();
		factory.setNamespaceAware(true);
		javax.xml.parsers.DocumentBuilder builder = null;
		try {
			builder = factory.newDocumentBuilder();
		} catch (javax.xml.parsers.ParserConfigurationException ex) {
		}
		org.w3c.dom.Document doc = builder.parse(is);
		is.close();
		return doc;
	}

	private Certificate getCertificate(String alias) {
		Certificate cert = null;
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("PKCS12");
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {

			ks.load(this.getClass().getResourceAsStream(PKCS12_RESOURCE),
					PKCS12_PASSWORD.toCharArray());
			cert = ks.getCertificate(alias);

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return cert;

	}

	private PrivateKey getPrivateKey(String alias) {
		PrivateKey prKey = null;
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("PKCS12");
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		try {
			ks.load(this.getClass().getResourceAsStream(PKCS12_RESOURCE),
					PKCS12_PASSWORD.toCharArray());
			try {

			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		if (ks != null) {
			try {
				prKey = (PrivateKey) ks.getKey("csi",
						PKCS12_PASSWORD.toCharArray());
			} catch (UnrecoverableKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

		return prKey;

	}

}
