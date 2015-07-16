package samlGabLib;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class SamlHeaderConfigFactory {

	private SamlHeaderConfigFactory() {
		// TODO Auto-generated constructor stub
	}

	public static SamlHeaderConfig newInstance() throws IOException {

		Properties configProperties = getPropertiesFile();
		SamlHeaderConfig config = loadConfig(configProperties);
		return config;
	}

	public static SamlHeaderConfig newInstance(String rutaProperties,
			boolean classpath) throws IOException {

		Properties configProperties = getPropertiesFile(rutaProperties,
				classpath);
		SamlHeaderConfig config = loadConfig(configProperties);
		return config;

	}

	private static Properties getPropertiesFile(String rutaProperties,
			boolean classpath) throws FileNotFoundException, IOException {
		Properties configProperties = new Properties();
		InputStream is = null;
		if (classpath) {
			is = SamlHeaderConfig.class.getClassLoader().getResourceAsStream(
					rutaProperties);
		} else {
			is = new FileInputStream(rutaProperties);
		}
		configProperties.load(is);
		return configProperties;
	}

	private static Properties getPropertiesFile() throws IOException {
		Properties configProperties = new Properties();
		InputStream is = SamlHeaderConfig.class.getClassLoader()
				.getResourceAsStream("samlGabLib/rsc/saml.properties");
		configProperties.load(is);
		return configProperties;
	}

	private static SamlHeaderConfig loadConfig(Properties configProperties) {

		SamlHeaderConfig config = new SamlHeaderConfig();

		config.VALOR_EMISOR_SAML = configProperties.getProperty(
				SamlHeaderConfig.CONST_EMISOR_SAML, "");

		config.VALOR_VALIDEZ_SAML = Integer.parseInt(configProperties
				.getProperty(SamlHeaderConfig.CONST_VALIDEZ_SAML, ""));

		config.VALOR_SECURITY_ALIAS = configProperties
				.getProperty(SamlHeaderConfig.CONST_SECURITY_ALIAS);

		config.VALOR_RUTA_MAGATZEM = configProperties
				.getProperty(SamlHeaderConfig.CONST_RUTA_MAGATZEM);

		config.VALOR_PASS_MAGATZEM = configProperties
				.getProperty(SamlHeaderConfig.CONST_PASS_MAGATZEM);

		config.VALOR_GET_FROM_CLASSPATH = Boolean.parseBoolean(configProperties
				.getProperty(SamlHeaderConfig.CONST_GET_FROM_CLASSPATH));

		return config;

	}

}
