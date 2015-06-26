package samlGabLib;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.opensaml.Configuration;
import org.opensaml.xml.security.SecurityConfiguration;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;

public class SecurityDataManager {

	//private final static String PKCS12_RESOURCE = "csiKeyStore.pkcs12";
	private final static String PKCS12_RESOURCE = "samlGabLib/rsc/csiKeyStore.pkcs12";
	private final static String PKCS12_ALIAS = "csi";
	/**
	 * <p>
	 * Constraseña de acceso a la clave privada del usuario
	 * </p>
	 */
	// public final static String PKCS12_PASSWORD = "facturae";
	private final static String PKCS12_PASSWORD = "5n9eDmVM";// hc3

	private Credential signingCredential = null;
	private KeyInfo keyInfo = null;
	private KeyStore keyStore = null;
	private Certificate certificate = null;
	private PrivateKey privateKey = null;
		
	protected SecurityDataManager(){
		loadKeyStore();
		loadPrivateKey(PKCS12_ALIAS);
		loadCertificate(PKCS12_ALIAS);	
		createCredentials();
		loadKeyInfo();
	}
	
	protected SecurityDataManager(String alias){
		loadKeyStore();
		loadPrivateKey(alias);
		
		loadCertificate(alias);
		createCredentials();
		loadKeyInfo();
	}
	
	private void loadKeyStore() {
		try {
			this.keyStore = KeyStore.getInstance("PKCS12");
			/*this.keyStore.load(this.getClass().getResourceAsStream(PKCS12_RESOURCE),
					PKCS12_PASSWORD.toCharArray());*/
			this.keyStore.load(this.getClass().getClassLoader().getResourceAsStream(PKCS12_RESOURCE),
					PKCS12_PASSWORD.toCharArray());
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
		
	}

	private void loadCertificate(String alias) {
		
		try {

			this.certificate = this.keyStore.getCertificate(alias);

		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	private void loadPrivateKey(String alias){

		if (this.keyStore != null) {
			try {
				this.privateKey = (PrivateKey) this.keyStore.getKey(alias,
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

	}
	
	private void loadKeyInfo(){

		SecurityConfiguration secConfiguration = Configuration
				.getGlobalSecurityConfiguration();
		NamedKeyInfoGeneratorManager namedKeyInfoGeneratorManager = secConfiguration
				.getKeyInfoGeneratorManager();
		KeyInfoGeneratorManager keyInfoGeneratorManager = namedKeyInfoGeneratorManager
				.getDefaultManager();
		KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager
				.getFactory(signingCredential);
		KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory
				.newInstance();

		try {
			this.keyInfo = keyInfoGenerator.generate(signingCredential);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	
	protected void createCredentials(){
		
		X509Certificate cert = (X509Certificate) getCertificate();
		PrivateKey prKey = getPrivateKey();
		BasicX509Credential credential = new BasicX509Credential();
		credential.setEntityCertificate(cert);
		credential.setPrivateKey(prKey);
		this.signingCredential= credential;
		
	}
	
	protected PrivateKey getPrivateKey() {
		return this.privateKey;
	}

	protected KeyInfo getKeyInfo() {
		return this.keyInfo;
	}
	
	protected Certificate getCertificate() {
		return this.certificate;
	}

	protected Credential getCredentials(){
		return this.signingCredential;
	}


}
