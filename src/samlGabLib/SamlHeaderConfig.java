package samlGabLib;

public class SamlHeaderConfig {

	
	
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
    protected final static String CONST_EMISOR_SAML = "emissorSAML";
    protected final static String CONST_RUTA_NAVEGADOR = "rutaNavegador";
    protected final static String CONST_RUTA_PAGINAS_HTML = "rutaPaginesHTML";
    protected final static String CONST_URLPOST_VISOR = "URLPostVisor";
    protected final static String CONST_VALIDEZ_SAML = "TempsValidesaSAML";
    protected final static String CONST_COD_MENSAJE_HCCSA = "codiMENhccsa";
    protected final static String CONST_BORRAR_HISTORICO_HTML = "esborrarHistoricHtml";
    protected final static  String CONST_SECURITY_ALIAS = "securityAlias";
    protected final static  String CONST_RUTA_MAGATZEM = "rutaMagatzem";
    protected final static  String CONST_GET_FROM_CLASSPATH = "getFromclasspath";
    
    protected final static  String CONST_PASS_MAGATZEM = "passwordMagatzem";
    

    // LOG
    private static String CONST_NIVEL_LOG = "nivellLog";
    private static String CONST_RUTA_LOG = "rutaLog";

    // VALOR SAML
    protected  String VALOR_EMISOR_SAML;
    protected  String VALOR_SECURITY_ALIAS;
    protected  String VALOR_RUTA_NAVEGADOR;
    protected  String VALOR_URLPOST_VISOR;
    protected  int VALOR_VALIDEZ_SAML;
    protected  String VALOR_RUTA_PAGINAS_HTML;
    protected  String VALOR_COD_MENSAJE_HCCSA;
    protected  String VALOR_BORRAR_HISTORICO_HTML;
    protected  String VALOR_RUTA_MAGATZEM;
    protected  String VALOR_PASS_MAGATZEM;
    protected  boolean VALOR_GET_FROM_CLASSPATH;
	
	
	protected SamlHeaderConfig() {
		// TODO Auto-generated constructor stub
	}

}
