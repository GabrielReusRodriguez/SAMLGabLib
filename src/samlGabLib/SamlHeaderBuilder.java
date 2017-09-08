package samlGabLib;

import java.io.IOException;
import java.io.StringWriter;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Iterator;
import java.util.List;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
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
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.w3c.dom.Element;

public class SamlHeaderBuilder {

	private SecurityDataManager securityDataManager = null;
	private SamlHeaderConfig config = null;
	private Element samlHeaderElement = null;
	private SamlHeaderCustomData customData = null;

	private void init(String rutaProperties,boolean classpath)
			throws ConfigurationException, IOException {
		this.config = SamlHeaderConfigFactory.newInstance(rutaProperties,classpath);
		DefaultBootstrap.bootstrap();
	}

	private void init() throws ConfigurationException, IOException {
		this.config = SamlHeaderConfigFactory.newInstance();
		DefaultBootstrap.bootstrap();
	}

	public SamlHeaderBuilder() throws SamlHeaderBuilderException {
		try {
			init();
			securityDataManager = new SecurityDataManager();
		} catch (ConfigurationException e) {
			throw new SamlHeaderBuilderException(e);
		} catch (IOException e) {
			throw new SamlHeaderBuilderException(e);
		}
	}

	public SamlHeaderBuilder(String ruta_properties,boolean classpath)
			throws SamlHeaderBuilderException {
		try {
			init(ruta_properties,classpath);
			securityDataManager = new SecurityDataManager(this.config);
		} catch (ConfigurationException e) {
			throw new SamlHeaderBuilderException(e);
		} catch (IOException e) {
			throw new SamlHeaderBuilderException(e);
		} catch (KeyStoreException e) {
			throw new SamlHeaderBuilderException(e);
		}
	}

	public String build(SamlHeaderCustomData customData) throws SamlHeaderBuilderException {

		String header = "";
		this.customData = customData;
		try {

			SignatureAlgorithm.registerDefaultAlgorithms();

			Assertion assertion = buildAssertion();

			Signature signature = (Signature) Configuration.getBuilderFactory()
					.getBuilder(Signature.DEFAULT_ELEMENT_NAME)
					.buildObject(Signature.DEFAULT_ELEMENT_NAME);

			signature
					.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);

			signature
					.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			signature.setKeyInfo(securityDataManager.getKeyInfo());

			signature
					.setSigningCredential(securityDataManager.getCredentials());

			// ES MUY IMPORTANTE HACER ESTO POR ESTE ORDEN, SI NO LA FIRMA NO
			// FUNCIONA.
			assertion.setSignature(signature);

			MarshallerFactory marshallerFactory = Configuration
					.getMarshallerFactory();

			Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
			Element assertionElement = marshaller.marshall(assertion);

			try {
				Signer.signObject(signature);

			} catch (SignatureException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				throw new SamlHeaderBuilderException(e1);
			}

			// printResult(assertionElement);
			this.samlHeaderElement = assertionElement;
			header = header2String(assertionElement);
		} catch (MarshallingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new SamlHeaderBuilderException(e);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new SamlHeaderBuilderException(e);
		}

		return header;
	}

	private Assertion buildAssertion() throws NoSuchAlgorithmException {
		AssertionBuilder ab = new AssertionBuilder();
		SecureRandomIdentifierGenerator idGenerator = new SecureRandomIdentifierGenerator();

		// Assertion.
		Assertion assertion = ab.buildObject();
		assertion.setVersion(SAMLVersion.VERSION_20);
		// assertion.setID("_cb7f518664f2199119a3d09c9927de60");
		assertion.setID(idGenerator.generateIdentifier());
		assertion.setIssueInstant(new DateTime());

		// Issuer
		IssuerBuilder ib = new IssuerBuilder();
		Issuer myIssuer = ib.buildObject();
		myIssuer.setValue(this.config.VALOR_EMISOR_SAML);
		assertion.setIssuer(myIssuer);

		// Subject
		SubjectBuilder sb = new SubjectBuilder();
		Subject mySubject = sb.buildObject();
		NameIDBuilder nb = new NameIDBuilder();
		NameID myNameID = nb.buildObject();
		// myNameID.setValue("CN=SAP, OU=Vegeu https://www.catcert.cat/verCDA-1 (c)03, OU=Serveis Públics de Certificació CDA-1, O=Consorci Sanitari Integral, C=ES");
		myNameID.setValue(securityDataManager.getDNFromCertificate());

		myNameID.setFormat(NameIdentifier.X509_SUBJECT);
		mySubject.setNameID(myNameID);
		assertion.setSubject(mySubject);

		ConditionsBuilder cb = new ConditionsBuilder();
		Conditions myConditions = cb.buildObject();
		// Creo la date con la condicion.
		DateTime dtToday = null;
		dtToday = new DateTime();

		DateTime dtNotAfter = null;
		dtNotAfter = new DateTime();
		// dtNotAfter = dtToday.plusMinutes(10);
		dtNotAfter = dtToday.plusSeconds(config.VALOR_VALIDEZ_SAML);

		// myConditions.setNotBefore("2015-03-16T12:32:26.024Z");
		myConditions.setNotBefore(dtToday);
		myConditions.setNotOnOrAfter(dtNotAfter);

		assertion.setConditions(myConditions);
		// myConditions.setNotOnOrAfter("2015-03-16T12:41:06.024Z");
		// myConditions.setNotBefore(new DateTime());
		// myConditions.setNotOnOrAfter(new DateTime());

		AttributeStatementBuilder attstmtb = new AttributeStatementBuilder();
		AttributeStatement attstmt = attstmtb.buildObject();

		
		//Campos personalizados.
		if(this.customData != null){
			List<DataPair> listaAserciones = this.customData.getList();
			DataPair valor = null;
			if(listaAserciones != null){
				Iterator<DataPair> it = listaAserciones.iterator();
				while(it.hasNext()){
					valor = (DataPair)it.next();
					assertion.getAttributeStatements().add(
							newAttribute(valor.getField(), valor.getValue(), attstmt));
				}
			}
		}
		/*
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
*/
		// user authenticated via X509 token
		/*
		 * AuthnStatementBuilder asb = new AuthnStatementBuilder();
		 * AuthnStatement myAuthnStatement = asb.buildObject();
		 * myAuthnStatement.setAuthnInstant(new DateTime()); AuthnContextBuilder
		 * acb = new AuthnContextBuilder(); AuthnContext myACI =
		 * acb.buildObject(); AuthnContextClassRefBuilder accrb = new
		 * AuthnContextClassRefBuilder(); AuthnContextClassRef accr =
		 * accrb.buildObject();
		 * accr.setAuthnContextClassRef(AuthnContext.X509_AUTHN_CTX);
		 * myACI.setAuthnContextClassRef(accr);
		 * myAuthnStatement.setAuthnContext(myACI);
		 * assertion.getAuthnStatements().add(myAuthnStatement);
		 */
		return assertion;
	}

	private void printResult(Element assertionElement) {
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

	private String header2String(Element assertionElement) {
		String header = "";
		Transformer transformer;
		try {

			transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
					"yes");
			StreamResult result = new StreamResult(new StringWriter());
			DOMSource source = new DOMSource(assertionElement.getParentNode());

			transformer.transform(source, result);
			header = result.getWriter().toString();
			// System.out.println(xmlString);

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
		return header;
	}

	private AttributeStatement newAttribute(String name, String value,
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
	
	public Element getSamlHeader(){
		return this.samlHeaderElement;
	}

}
