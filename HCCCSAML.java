

import es.sia.utils.ini.SIAIni;
import es.sia.utils.ini.Seccion;
import es.sia.utils.SIALogger;
import es.sia.utils.SIAUtils;
import es.sia.exceptions.SIAException;

import java.util.Enumeration;
import java.util.Properties;
import java.util.HashMap;
import java.util.ResourceBundle;
import java.io.*;
import java.net.URL;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;

import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.saml2.core.*;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.*;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.bouncycastle.util.encoders.Base64;

public class HCCCSAML {

    // OPERACIONES
    public static String OP_INICIALIZAR_API = "00";
    public static String OP_GENERAR_SAML = "01";
    public static String OP_GENERAR_HTML = "02";
    public static String OP_POST_SAML = "03";
    public static String OP_ALMACEN_ATRIBUTOS = "04";
    public static String OP_ALMACEN_CERTIFICADOS = "05";
    public static String OP_PRUEBAS_SAML = "06";

    // SECCIONES
    private static String CONST_SECCION_SAML = "SAML";
    private static String CONST_SECCION_LOG = "LOG";

    // SAML
    private static String CONST_EMISOR_SAML = "emissorSAML";
    private static String CONST_RUTA_NAVEGADOR = "rutaNavegador";
    private static String CONST_RUTA_PAGINAS_HTML = "rutaPaginesHTML";
    private static String CONST_URLPOST_VISOR = "URLPostVisor";
    private static String CONST_VALIDEZ_SAML = "TempsValidesaSAML";
    private static String CONST_COD_MENSAJE_HCCSA = "codiMENhccsa";
    private static String CONST_BORRAR_HISTORICO_HTML = "esborrarHistoricHtml";

    // LOG
    private static String CONST_NIVEL_LOG = "nivellLog";
    private static String CONST_RUTA_LOG = "rutaLog";

    // VALOR SAML
    private static String VALOR_EMISOR_SAML;
    private static String VALOR_RUTA_NAVEGADOR;
    private static String VALOR_URLPOST_VISOR;
    private static long VALOR_VALIDEZ_SAML;
    private static String VALOR_RUTA_PAGINAS_HTML;
    public static String VALOR_COD_MENSAJE_HCCSA;
    public static String VALOR_BORRAR_HISTORICO_HTML;

    private static HashMap MENSAJES = new HashMap();

    private HCCCX509 X509;

    private XMLObjectBuilderFactory builderFactory;

    static{
        try{
            carregarMissatges();
        }catch(SIAException e){
            //SIALogger.println("static",SIALogger.LEV_ERR,"[" + OP_INICIALIZAR_API + "]" + " Error al cargar los mensajes.");
            System.out.println("[" + OP_INICIALIZAR_API + "]" + " Error al cargar los mensajes.");
        }catch(ClassNotFoundException e){
            //SIALogger.println("static",SIALogger.LEV_ERR,"[" + OP_INICIALIZAR_API + "] Error al cargar los mensajes de error. ClassNotFoundException");
            System.out.println("[" + OP_INICIALIZAR_API + "] Error al cargar los mensajes de error. ClassNotFoundException");        }
    }

    
    
    public HCCCSAML(String initFile, boolean flag)  throws SIAException{
        String OPERACION = OP_INICIALIZAR_API;
        String MEN;
        
        ResourceBundle bundle = ResourceBundle.getBundle(initFile);
        
        StringBuffer inputConfig =  new StringBuffer();
        
        try{
        	
        	generaConfig(bundle,inputConfig);
        	SIAIni ini = new SIAIni(new ByteArrayInputStream(inputConfig.toString().getBytes()));
            VALOR_COD_MENSAJE_HCCSA = ini.getString(CONST_SECCION_SAML,CONST_COD_MENSAJE_HCCSA,"00");

            X509 = new HCCCX509(ini);

            String rutaLog = ini.getString(CONST_SECCION_LOG,CONST_RUTA_LOG,"");
			String fichero="";
            if (rutaLog.lastIndexOf(File.separator)!=-1) {
            	fichero = rutaLog.substring(0,rutaLog.lastIndexOf(File.separator));
            } else {
            	fichero = rutaLog;
            }            
            //File fileRutaLog = new File(rutaLog.substring(0,rutaLog.lastIndexOf("\\")));
            File fileRutaLog = new File(fichero);            
            if(!fileRutaLog.exists()){
                MEN = "06";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            // SE INIZIALIZA EL LOG
            if (SIALogger.getLogPath() == null){
                // Se establecen las propiedades para la generaci�n de logs.
                SIALogger.setProperty(SIALogger.P_LOG_LEVEL, ini.getString(CONST_SECCION_LOG,CONST_NIVEL_LOG,"3"));
                SIALogger.setProperty(SIALogger.P_LOG_FILE,rutaLog);
                SIALogger.setProperty(SIALogger.P_LOGS_TO_FILE, String.valueOf(1));
                SIALogger.setProperty(SIALogger.P_LOGS_TO_CONSOLE, String.valueOf(0));
                SIALogger.setProperty(SIALogger.P_PRINT_DATE, String.valueOf(1));                
            }
            SIALogger.println(this,SIALogger.LEV_INF,"Log inicializado.");

            VALOR_EMISOR_SAML = ini.getString(CONST_SECCION_SAML,CONST_EMISOR_SAML);
            VALOR_RUTA_NAVEGADOR = ini.getString(CONST_SECCION_SAML,CONST_RUTA_NAVEGADOR);
            VALOR_URLPOST_VISOR = ini.getString(CONST_SECCION_SAML,CONST_URLPOST_VISOR);
            String sVALOR_VALIDEZ_SAML = ini.getString(CONST_SECCION_SAML,CONST_VALIDEZ_SAML,"60");
            VALOR_RUTA_PAGINAS_HTML = ini.getString(CONST_SECCION_SAML,CONST_RUTA_PAGINAS_HTML);
            VALOR_BORRAR_HISTORICO_HTML = ini.getString(CONST_SECCION_SAML,CONST_BORRAR_HISTORICO_HTML,"no");

            File fileRutaNavegador = new File(VALOR_RUTA_NAVEGADOR);
            if(!fileRutaNavegador.exists()){
                MEN = "02";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            File fileRutaPaginasHTML = new File(VALOR_RUTA_PAGINAS_HTML);
            if(!fileRutaPaginasHTML.exists()){
                MEN = "03";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            try {
                URL urlPOST_VISOR = new URL(VALOR_URLPOST_VISOR);
            } catch (MalformedURLException e) {
                MEN = "04";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            try{
                VALOR_VALIDEZ_SAML = Integer.parseInt(sVALOR_VALIDEZ_SAML);
            }catch(NumberFormatException e){
                MEN = "05";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            if(VALOR_BORRAR_HISTORICO_HTML.equals("si") && VALOR_BORRAR_HISTORICO_HTML.equals("no")){
                MEN = "08";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            SIALogger.println(this,SIALogger.LEV_INF,"Propiedades obtenidas correctamente.");


            Configuration.init();
            builderFactory = Configuration.getBuilderFactory();

            SIALogger.println(this,SIALogger.LEV_INF,"API INICIALIZADA");
            
        }catch(SIAException e){
            MEN = "00";
            SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
            throw e;
        }
        
        
        
        
        
        /*ORIGINAL*/
/*
        try{
            File fileConf = new File(rutaIni);
            if(!fileConf.exists()){
                MEN = "07";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + OPERACION + MEN + "] " + HCCCSAML.getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(OPERACION + MEN);
                hccce.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
                throw hccce;
            }


            
            SIAIni ini = new SIAIni(rutaIni);

            VALOR_COD_MENSAJE_HCCSA = ini.getString(CONST_SECCION_SAML,CONST_COD_MENSAJE_HCCSA,"00");

            X509 = new HCCCX509(ini);

            String rutaLog = ini.getString(CONST_SECCION_LOG,CONST_RUTA_LOG,"");
			String fichero="";
            if (rutaLog.lastIndexOf(File.separator)!=-1) {
            	fichero = rutaLog.substring(0,rutaLog.lastIndexOf(File.separator));
            } else {
            	fichero = rutaLog;
            }            
            //File fileRutaLog = new File(rutaLog.substring(0,rutaLog.lastIndexOf("\\")));
            File fileRutaLog = new File(fichero);            
            if(!fileRutaLog.exists()){
                MEN = "06";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            // SE INIZIALIZA EL LOG
            if (SIALogger.getLogPath() == null){
                // Se establecen las propiedades para la generaci�n de logs.
                SIALogger.setProperty(SIALogger.P_LOG_LEVEL, ini.getString(CONST_SECCION_LOG,CONST_NIVEL_LOG,"3"));
                SIALogger.setProperty(SIALogger.P_LOG_FILE,rutaLog);
                SIALogger.setProperty(SIALogger.P_LOGS_TO_FILE, String.valueOf(1));
                SIALogger.setProperty(SIALogger.P_LOGS_TO_CONSOLE, String.valueOf(0));
                SIALogger.setProperty(SIALogger.P_PRINT_DATE, String.valueOf(1));                
            }
            SIALogger.println(this,SIALogger.LEV_INF,"Log inicializado.");

            VALOR_EMISOR_SAML = ini.getString(CONST_SECCION_SAML,CONST_EMISOR_SAML);
            VALOR_RUTA_NAVEGADOR = ini.getString(CONST_SECCION_SAML,CONST_RUTA_NAVEGADOR);
            VALOR_URLPOST_VISOR = ini.getString(CONST_SECCION_SAML,CONST_URLPOST_VISOR);
            String sVALOR_VALIDEZ_SAML = ini.getString(CONST_SECCION_SAML,CONST_VALIDEZ_SAML,"60");
            VALOR_RUTA_PAGINAS_HTML = ini.getString(CONST_SECCION_SAML,CONST_RUTA_PAGINAS_HTML);
            VALOR_BORRAR_HISTORICO_HTML = ini.getString(CONST_SECCION_SAML,CONST_BORRAR_HISTORICO_HTML,"no");

            File fileRutaNavegador = new File(VALOR_RUTA_NAVEGADOR);
            if(!fileRutaNavegador.exists()){
                MEN = "02";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            File fileRutaPaginasHTML = new File(VALOR_RUTA_PAGINAS_HTML);
            if(!fileRutaPaginasHTML.exists()){
                MEN = "03";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            try {
                URL urlPOST_VISOR = new URL(VALOR_URLPOST_VISOR);
            } catch (MalformedURLException e) {
                MEN = "04";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            try{
                VALOR_VALIDEZ_SAML = Integer.parseInt(sVALOR_VALIDEZ_SAML);
            }catch(NumberFormatException e){
                MEN = "05";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            if(VALOR_BORRAR_HISTORICO_HTML.equals("si") && VALOR_BORRAR_HISTORICO_HTML.equals("no")){
                MEN = "08";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            SIALogger.println(this,SIALogger.LEV_INF,"Propiedades obtenidas correctamente.");


            Configuration.init();
            builderFactory = Configuration.getBuilderFactory();

            SIALogger.println(this,SIALogger.LEV_INF,"API INICIALIZADA");

        }catch(SIAException e){
            MEN = "00";
            SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
            throw e;
        }
*/
    }
    
    
    private void generaConfig(ResourceBundle bundle, StringBuffer inputConfig) {
		// TODO Auto-generated method stub
		
	}


	/**
     * Constructor de la clase.
     * @param rutaIni Ruta al fichero de configuraci�n del API
     * @throws SIAException Excepci�n que se propaga en caso de error. C�digo de error y descripci�n.
     */
    public HCCCSAML(String rutaIni) throws SIAException{
        String OPERACION = OP_INICIALIZAR_API;
        String MEN;

        try{
            File fileConf = new File(rutaIni);
            if(!fileConf.exists()){
                MEN = "07";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + OPERACION + MEN + "] " + HCCCSAML.getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(OPERACION + MEN);
                hccce.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
                throw hccce;
            }

            SIAIni ini = new SIAIni(rutaIni);

            VALOR_COD_MENSAJE_HCCSA = ini.getString(CONST_SECCION_SAML,CONST_COD_MENSAJE_HCCSA,"00");

            X509 = new HCCCX509(ini);

            String rutaLog = ini.getString(CONST_SECCION_LOG,CONST_RUTA_LOG,"");
			String fichero="";
            if (rutaLog.lastIndexOf(File.separator)!=-1) {
            	fichero = rutaLog.substring(0,rutaLog.lastIndexOf(File.separator));
            } else {
            	fichero = rutaLog;
            }            
            //File fileRutaLog = new File(rutaLog.substring(0,rutaLog.lastIndexOf("\\")));
            File fileRutaLog = new File(fichero);            
            if(!fileRutaLog.exists()){
                MEN = "06";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            // SE INIZIALIZA EL LOG
            if (SIALogger.getLogPath() == null){
                // Se establecen las propiedades para la generaci�n de logs.
                SIALogger.setProperty(SIALogger.P_LOG_LEVEL, ini.getString(CONST_SECCION_LOG,CONST_NIVEL_LOG,"3"));
                SIALogger.setProperty(SIALogger.P_LOG_FILE,rutaLog);
                SIALogger.setProperty(SIALogger.P_LOGS_TO_FILE, String.valueOf(1));
                SIALogger.setProperty(SIALogger.P_LOGS_TO_CONSOLE, String.valueOf(0));
                SIALogger.setProperty(SIALogger.P_PRINT_DATE, String.valueOf(1));                
            }
            SIALogger.println(this,SIALogger.LEV_INF,"Log inicializado.");

            VALOR_EMISOR_SAML = ini.getString(CONST_SECCION_SAML,CONST_EMISOR_SAML);
            VALOR_RUTA_NAVEGADOR = ini.getString(CONST_SECCION_SAML,CONST_RUTA_NAVEGADOR);
            VALOR_URLPOST_VISOR = ini.getString(CONST_SECCION_SAML,CONST_URLPOST_VISOR);
            String sVALOR_VALIDEZ_SAML = ini.getString(CONST_SECCION_SAML,CONST_VALIDEZ_SAML,"60");
            VALOR_RUTA_PAGINAS_HTML = ini.getString(CONST_SECCION_SAML,CONST_RUTA_PAGINAS_HTML);
            VALOR_BORRAR_HISTORICO_HTML = ini.getString(CONST_SECCION_SAML,CONST_BORRAR_HISTORICO_HTML,"no");

            File fileRutaNavegador = new File(VALOR_RUTA_NAVEGADOR);
            if(!fileRutaNavegador.exists()){
                MEN = "02";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            File fileRutaPaginasHTML = new File(VALOR_RUTA_PAGINAS_HTML);
            if(!fileRutaPaginasHTML.exists()){
                MEN = "03";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            try {
                URL urlPOST_VISOR = new URL(VALOR_URLPOST_VISOR);
            } catch (MalformedURLException e) {
                MEN = "04";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            try{
                VALOR_VALIDEZ_SAML = Integer.parseInt(sVALOR_VALIDEZ_SAML);
            }catch(NumberFormatException e){
                MEN = "05";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            if(VALOR_BORRAR_HISTORICO_HTML.equals("si") && VALOR_BORRAR_HISTORICO_HTML.equals("no")){
                MEN = "08";
                SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
                SIAException hccce = new SIAException();
                hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                hccce.setDescription(getMissatge(OPERACION,MEN));
                throw hccce;
            }

            SIALogger.println(this,SIALogger.LEV_INF,"Propiedades obtenidas correctamente.");


            Configuration.init();
            builderFactory = Configuration.getBuilderFactory();

            SIALogger.println(this,SIALogger.LEV_INF,"API INICIALIZADA");

        }catch(SIAException e){
            MEN = "00";
            SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
            throw e;
        }
    }

    /**
     * Este m�todo devuelve la descripci�n dado el c�digo de un mensaje.
     * @param codigo C�digo del que se quiere la descripci�n.
     * @return Se devuelve el mensaje asociado al c�digo.
     */
    public static String getMissatge(String codigo){
        return (String)MENSAJES.get(codigo);
    }

    /**
     * Este m�todo devuelve la descripci�n dado el c�digo de operaci�n y c�digo del mensaje.
     * @param codOperacio C�digo de la operaci�n de la que se quiere obtener el mensaje.
     * @param codMissatge C�digo del mensaje que se quiere obtener.
     * @return Se devuelve el mensaje asociado al c�digo de operaci�n y c�digo del mensaje.
     */
    public static String getMissatge(String codOperacio,String codMissatge){
        return (String)MENSAJES.get(codOperacio + codMissatge);
    }

    /**
     * Este m�todo devuelve la descripci�n dado el c�digo de operaci�n y c�digo del mensaje.
     * @param codOperacio C�digo de la operaci�n de la que se quiere obtener el mensaje.
     * @param codMissatge C�digo del mensaje que se quiere obtener.
     * @return Se devuelve el mensaje asociado al c�digo de operaci�n y c�digo del mensaje.
     */
    public static String getMissatge(int codOperacio,String codMissatge){
        return getMissatge("" + codOperacio,"" + codMissatge);
    }

    /**
     * M�todo privado de clase que carga los mensajes al inicializar la clase.
     * @throws ClassNotFoundException Excepci�n que se prograga si no se ha encontrado la clase.
     * @throws SIAException Excepci�n que se propaga en caso de error. C�digo de error y descripci�n.
     */
    private static void carregarMissatges() throws ClassNotFoundException,SIAException{
        // SE OBTIENEN LOS MENSAJES        
        SIAIni iniMensajes = new SIAIni(Class.forName(HCCCSAML.class.getName()).getResourceAsStream("/es/hccc/saml/hccsa_mensajes.properties"));
        Enumeration eSecciones = iniMensajes.getSectionNames();
        Seccion oSeccion;
        Properties pSeccion;
        String sNombreSeccion;
        Enumeration ePropiedades;
        String clave;
        while(eSecciones.hasMoreElements()){
            oSeccion = (Seccion)eSecciones.nextElement();
            sNombreSeccion = oSeccion.devolverNombre();
            pSeccion = iniMensajes.getPropertiesSection(sNombreSeccion);
            ePropiedades = pSeccion.keys();
            while(ePropiedades.hasMoreElements()){
                clave = (String)ePropiedades.nextElement();
                MENSAJES.put(sNombreSeccion + "" + clave,pSeccion.getProperty(clave,"").replaceAll("([\'])", "\\\\$1"));
            }
        }
        SIALogger.println("HCCCSAML.carregarMissatges()",SIALogger.LEV_INF,"Se obtienen los mensajes.");
    }

    public Assertion getAssertion(HCCCAtributsSAML atributs) throws SIAException{
        String OPERACION = OP_GENERAR_SAML;
        String MEN;
        Assertion assertion = null;

        try{
        		//System.setProperty("file.encoding", "ISO-8859-15");
        		System.setProperty("file.encoding", "UTF-8");
        		
            MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

            AssertionBuilder assertionBuilder = (AssertionBuilder) builderFactory.getBuilder(Assertion.DEFAULT_ELEMENT_NAME);
            IssuerBuilder issuerBuilder = (IssuerBuilder) builderFactory.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
            AuthnStatementBuilder authnStatementBuilder = (AuthnStatementBuilder) builderFactory.getBuilder(AuthnStatement.DEFAULT_ELEMENT_NAME);
            SubjectBuilder subjectBuilder = (SubjectBuilder) builderFactory.getBuilder(Subject.DEFAULT_ELEMENT_NAME);
            NameIDBuilder nameIDBuilder = (NameIDBuilder) builderFactory.getBuilder(NameID.DEFAULT_ELEMENT_NAME);
            ConditionsBuilder conditionsBuilder = (ConditionsBuilder) builderFactory.getBuilder(Conditions.DEFAULT_ELEMENT_NAME);

            SecureRandomIdentifierGenerator idGenerator = new SecureRandomIdentifierGenerator();

            DateTime now = new DateTime();

            SIALogger.println("HCCCSAML.getSAML()",SIALogger.LEV_DEB,"Se crea la aserción.");
            assertion = assertionBuilder.buildObject();            
            assertion.setVersion(SAMLVersion.VERSION_20);
            assertion.setID(idGenerator.generateIdentifier());
            assertion.setIssueInstant(now);

            Issuer issuer = issuerBuilder.buildObject();
            issuer.setValue(VALOR_EMISOR_SAML);
            assertion.setIssuer(issuer);
            SIALogger.println("HCCCSAML.getSAML()",SIALogger.LEV_DEB,"Se añade el emisor a la aserción.");

            // SUBJECT
            Subject subject = subjectBuilder.buildObject();

            // NAMEID
            NameID nameID = nameIDBuilder.buildObject();
            nameID.setValue(X509.getDN());
            subject.setNameID(nameID);
            SIALogger.println("HCCCSAML.getSAML()",SIALogger.LEV_DEB,"Se añade el NameId a la aserción.");

            assertion.setSubject(subject);
            
            // CONDITIONS
            Conditions conditions = conditionsBuilder.buildObject();
            
            //Generar el SAML con el campo notBefore un poco por delante de la hora actual del equipo (3 minutos), 
            //si ahora se crea con la hora actual del equipo
            //conditions.setNotBefore(now);
            conditions.setNotBefore(new DateTime(now.getMillis() -  180000));            
            conditions.setNotOnOrAfter(new DateTime(now.getMillis() + (VALOR_VALIDEZ_SAML * 1000)));
            assertion.setConditions(conditions);
            SIALogger.println("HCCCSAML.getSAML()",SIALogger.LEV_DEB,"Se establecen las condiciones.");

            // AuthnStatement
            /*AuthnStatement authnStmt = authnStatementBuilder.buildObject();
            authnStmt.setAuthnInstant(now);
            assertion.getAuthnStatements().add(authnStmt);*/

            // ATRIBUTOS
            assertion.getAttributeStatement().add(atributs.getAtributs());            

            SignatureBuilder signatureBuilder = (SignatureBuilder) builderFactory.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
            KeyInfoBuilder keyInfoBuilder = (KeyInfoBuilder) builderFactory.getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);

            // SIGNATURE
            Signature signature = signatureBuilder.buildObject();
            signature.setSigningKey(X509.getClauPrivada());
            signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
            signature.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1);
            signature.getContentReferences().add(new HCCCSAMLObjectContentReference(assertion));
            SIALogger.println("HCCCSAML.getSAML()",SIALogger.LEV_DEB,"Se establece el reference.");

            KeyInfo keyInfo = keyInfoBuilder.buildObject();
            keyInfo.getCertificates().add(X509.getCertificate());
            signature.setKeyInfo(keyInfo);
            SIALogger.println("HCCCSAML.getSAML()",SIALogger.LEV_DEB,"Se establece el KeyInfo.");

            assertion.setSignature(signature);
            SIALogger.println("HCCCSAML.getSAML()",SIALogger.LEV_DEB,"Se establece el Signature.");

            Marshaller marshaller = marshallerFactory.getMarshaller(assertion);
            marshaller.marshall(assertion);
            SIALogger.println("HCCCSAML.getSAML()",SIALogger.LEV_DEB,"Se ordena la aserción.");

            Signer.signObject(signature);            
            SIALogger.println("HCCCSAML.getSAML()",SIALogger.LEV_DEB,"Se firma la aserción.");

        } catch (MarshallingException e) {
            MEN = "00";
            SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + getMissatge(OPERACION,MEN));
            SIAException hccce = new SIAException(e);
            hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            hccce.setDescription(getMissatge(OPERACION,MEN));
        }

        return assertion;
    }
    /**
     * Este m�todo devuelve un String con la aserci�n SAML firmado.
     * @param atributs Objeto de la clase HCCCAtributsSAML con los atributs que se quieren en la aserci�n SAML.
     * @return Devuelve un String con la aserci�n SAML firmada.
     * @throws SIAException Excepci�n que se propaga en caso de error. C�digo de error y descripci�n.
     */
    public String getSAML(HCCCAtributsSAML atributs) throws SIAException{
    	Assertion assertion = getAssertion(atributs);
        StringWriter stringWriter = new StringWriter();
        XMLHelper.writeNode(assertion.getDOM(),stringWriter);

        return stringWriter.toString();
    }

    /**
     * Este m�todo genera una página HTML en una ruta especificada en el fichero de configuraci�n de la clase, con una
     * aserci�n SAML en un campo oculto de un formulario.
     * @param atributs Objeto de la clase HCCCAtributsSAML con los atributs que se quieren en la aserci�n SAML.
     * @throws SIAException Excepci�n que se propaga en caso de error. C�digo de error y descripci�n.
     */
    public void generaHTML(HCCCAtributsSAML atributs) throws SIAException{
        String OPERACION = OP_GENERAR_HTML;
        String MEN = "";
        String paginaHTML;

        try{
            if(VALOR_BORRAR_HISTORICO_HTML.equals("si")){
                SIALogger.println("HCCCSAML.generaHTML()",SIALogger.LEV_INF,"Se borra el histórico de páginas HTML generadas.");
                esborraFitxersHtml(VALOR_RUTA_PAGINAS_HTML);
            }               

            // SE GENERA LA P�GINA HTML
            paginaHTML = getHTML(atributs);
            SIALogger.println("HCCCSAML.generaHTML()",SIALogger.LEV_DEB,"Se genera la página con la aserción escapada.");

            // SE GUARDA LA PAGINA HTML
            File filePaginaHTML = File.createTempFile("HCC",".html",new File(VALOR_RUTA_PAGINAS_HTML));
            SIAUtils.writeToFile(filePaginaHTML.getAbsolutePath(),paginaHTML,false);
            SIALogger.println("HCCCSAML.generaHTML()",SIALogger.LEV_DEB,"Se genera crea la página HTML.");

            String exec = "\"" + VALOR_RUTA_NAVEGADOR + "\" \"" + filePaginaHTML.getAbsolutePath() + "\"";
            SIALogger.println("HCCCSAML.generaHTML()", SIALogger.LEV_DEB, "Executant: " + exec);
            // SE ABRE EL NAVEGADOR CON LA PAGINA                        
            Runtime.getRuntime().exec(exec);
            
            SIALogger.println("HCCCSAML.generaHTML()",SIALogger.LEV_DEB,"Se abre el navegador con la página.");
        }catch(SIAException e){
            SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(this,SIALogger.LEV_DEB, e.getMessage());
            throw e;
        } catch (IOException e) {
            MEN = "00";
            SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(this,SIALogger.LEV_DEB, e.getMessage());
            SIAException hccce = new SIAException(e);
            hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            hccce.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            throw hccce;
        }
    }

     /**
     * Este m�todo genera una página HTML en una ruta especificada en el fichero de configuraci�n de la clase, con una
     * aserci�n SAML en un campo oculto de un formulario.
     * @param atributs Objeto de la clase HCCCAtributsSAML con los atributs que se quieren en la aserci�n SAML.
     * @throws SIAException Excepci�n que se propaga en caso de error. C�digo de error y descripci�n.
     */
    public String getHTML(HCCCAtributsSAML atributs) throws SIAException, IOException {
        String OPERACION = OP_GENERAR_HTML;
        String MEN = "";
        char cr = 13;
        char lf = 10;
        char tb = 9;
        String cabeceraHTML = "<!-- saved from url=(0013)about:internet -->" + cr + lf + 
        		"<html>" + cr + lf + 
                "<head>" + cr + lf +
                "<title>Hist&ograve;ria Cl&iacute;nica Compartida a Catalunya</title>" + cr + lf +
                "</head>" + cr + lf +
                "<body onload=\"document.formulario.submit();\">" + cr + lf +
                "<form method=\"post\" name=\"formulario\" action=\"" + VALOR_URLPOST_VISOR + "\">" + cr + lf +
                tb + "<input type=\"hidden\" name=\"SAMLResponse\" value=\"";

        String pieHTML = "\">" + tb + cr + lf +
                "</form>" + cr + lf +
                "</body>" + cr + lf +
                "</html>";

        String paginaHTML;

        try{
            // SE OBTIENE LA ASERCI�N SAML
            String SAML = getSAML(atributs);
            SIALogger.println("HCCCSAML.generaHTML()",SIALogger.LEV_DEB,"Se genera la aserción.");

            // SE GENERA LA P�GINA HTML
            //paginaHTML = cabeceraHTML + XMLUtils.XMLEncoder(SAML) + pieHTML;
            paginaHTML = cabeceraHTML + new String(Base64.encode(SAML.getBytes("UTF-8"))) + pieHTML;
            SIALogger.println("HCCCSAML.generaHTML()",SIALogger.LEV_DEB,"Se genera la página con la aserción escapada.");

        }catch(SIAException e){
            SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + HCCCSAML.getMissatge(OPERACION,MEN));
            throw e;
        }

        return paginaHTML;
    }

    /**
     * Este m�todo visualiza por consola un elemento XMLObject.
     * @param metadata Objeto XMLObject que se quiere imprimir.
     */
    public static void ver(XMLObject metadata) {
        System.out.println(XMLHelper.nodeToString(metadata.getDOM()));
    }

    /**
     * Este m�todo devuelve una instancia de la clase HCCCAtributsSAML, utilizada como almac�n de atributs.
     * @return Se devuelve una instancia del almac�n de atributs.
     */
    public HCCCAtributsSAML getInstanciaAtributs(){
        return new HCCCAtributsSAML(builderFactory);
    }

    /**
     * Este m�todo permite realizar un POST sobre una URL dado una aserci�n SAML.
     * @param saml Aserci�n SAML con lo que se va realizar el POST.
     * @throws SIAException Excepci�n que se propaga en caso de error. C�digo de error y descripci�n.
     */
    public void postSAML(String saml) throws SIAException{
        String OPERACION = OP_POST_SAML;
        String MEN;
        try {
            URL url = new URL (VALOR_URLPOST_VISOR);

            HttpURLConnection httpConnection = (HttpURLConnection) url.openConnection();
            httpConnection.setDoOutput(true);
            httpConnection.setDoInput(true);
            httpConnection.setRequestMethod("POST");
						httpConnection.setRequestProperty("Accept-Charset", "UTF-8");
						//httpConnection.setRequestProperty("Accept-Charset", "ISO-8859-15");
            //httpConnection.getOutputStream().write(saml.getBytes());
            httpConnection.getOutputStream().write(saml.getBytes("UTF-8"));

            System.out.println ("Response Code = " + httpConnection.getResponseCode());
            System.out.println ("Response Message = " + httpConnection.getResponseMessage());
            System.out.println ("Response = " + httpConnection.toString());

            if(httpConnection.getResponseCode() != 200){
                // Se imprime la salida de error.
                InputStream is = httpConnection.getErrorStream();
                InputStreamReader isr = new InputStreamReader(is);
                BufferedReader br = new BufferedReader(isr);
                while (br.ready()){
                    String line = br.readLine();
                    System.out.println (line);
                }
            }
        } catch (MalformedURLException e) {
            MEN = "00";
            SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + HCCCSAML.getMissatge(OPERACION,MEN));
            SIAException hccce = new SIAException(e);
            hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            hccce.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            throw hccce;
        } catch (IOException e) {
            MEN = "01";
            SIALogger.println(this,SIALogger.LEV_ERR,"[" + VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN + "] " + HCCCSAML.getMissatge(OPERACION,MEN));
            SIAException hccce = new SIAException(e);
            hccce.setErrorCode(VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            hccce.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            throw hccce;
        }
    }

    private static void esborraFitxersHtml(String ruta){
        File carpeta = new File(ruta);

        File[] paginasAntiguas = carpeta.listFiles(new FileFilter() {
                                                        public boolean accept(File f) {
                                                            String name = f.getName();
                                                            return name.endsWith(".html");
                                                        }
                                                    });
        for(int i=0;i<paginasAntiguas.length;i++){
            paginasAntiguas[i].delete();
        }
    }
}