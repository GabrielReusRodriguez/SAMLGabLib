package samlGabLib.test;

import java.io.IOException;
import java.security.KeyStoreException;

import org.opensaml.xml.ConfigurationException;

import samlGabLib.SamlHeaderBuilder;
import samlGabLib.SamlHeaderBuilderException;

public class Test {


	public Test() {

	}

	public static void main(String[] args) {
		build_v2();
	}
	
	
	private static void build_v2(){
		
		SamlHeaderBuilder builder = null;
		try{
			builder = new SamlHeaderBuilder("samlGabLib/rsc/saml.properties",true);
		}catch(SamlHeaderBuilderException e){
			e.printStackTrace();
			return;
		}
		String header;
		try {
			header = builder.build();
			System.out.println(header);
		} catch (SamlHeaderBuilderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}

}
