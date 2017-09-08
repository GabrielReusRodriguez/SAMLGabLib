

import es.sia.utils.ini.SIAIni;
import es.sia.utils.SIALogger;
import es.sia.exceptions.SIAException;

import java.security.*;
import java.security.cert.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Enumeration;

import org.opensaml.xml.util.DatatypeHelper;


public class HCCCX509 {

    private static String CONST_SECCION_CIFRADO = "CIFRADO";

    private static String CONST_RUTA_ALMACEN = "rutaMagatzem";
    private static String CONST_NUMERO_SERIE_CERT = "numeroSerieCert";
    private static String CONST_PASSWORD_ALMACEN = "passwordMagatzem";

    private static String VALOR_NUMERO_SERIE_CERT;
    private static String VALOR_PASSWORD_ALMACEN;

    private KeyStore ALMACEN_CLAVES;
    private String TIPO_ALMACEN = "PKCS12";
    private X509Certificate X509;

    /**
     * Constructor de la clase por defecto.
     */
    public HCCCX509(){}

    /**
     * Constructor de la clase que recibe un fichero de configuración.
     * @param ini Objeto de la clase SIAIni con la configuración de la clase.
     * @throws SIAException Excepción que se propaga en caso de error. Código de error y descripción.
     */
    public HCCCX509(SIAIni ini) throws SIAException{
        String OPERACION  = HCCCSAML.OP_ALMACEN_CERTIFICADOS;
        String MEN;

        String ruta_almacen = ini.getString(CONST_SECCION_CIFRADO,CONST_RUTA_ALMACEN);
        VALOR_NUMERO_SERIE_CERT = ini.getString(CONST_SECCION_CIFRADO,CONST_NUMERO_SERIE_CERT,"");
        VALOR_PASSWORD_ALMACEN = ini.getStringCipher(CONST_SECCION_CIFRADO,CONST_PASSWORD_ALMACEN,"sia123");
				
				SIALogger.println(this,SIALogger.LEV_DEB,"HCCCX509 INVOCADO");
        SIALogger.println(this,SIALogger.LEV_DEB,CONST_RUTA_ALMACEN + "=" + ruta_almacen);
        SIALogger.println(this,SIALogger.LEV_DEB,CONST_PASSWORD_ALMACEN + "=" + VALOR_PASSWORD_ALMACEN);

        if(VALOR_NUMERO_SERIE_CERT.equals("")){
            MEN = "08";
            SIAException siae = new SIAException();
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(this,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        }

        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        ALMACEN_CLAVES = getMagatzemClaus(ruta_almacen,TIPO_ALMACEN,VALOR_PASSWORD_ALMACEN);

        try {
            String alias;
            Enumeration enume = ALMACEN_CLAVES.aliases();
            while(enume.hasMoreElements()){
                alias = (String)enume.nextElement();
                SIALogger.println(this,SIALogger.LEV_DEB,"Alias: " + alias);
                X509 = (X509Certificate)ALMACEN_CLAVES.getCertificate(alias);
                //SIALogger.println(this,SIALogger.LEV_DEB,"Número de serie: " + Integer.toHexString(X509.getSerialNumber().intValue()).equals(VALOR_NUMERO_SERIE_CERT.replaceAll(":","")));
                SIALogger.println(this,SIALogger.LEV_DEB,"Numero de serie: " + X509.getSerialNumber());
                SIALogger.println(this,SIALogger.LEV_DEB,"Tipo: " + X509.getType());
                SIALogger.println(this,SIALogger.LEV_DEB,"Dn: " + X509.getSubjectDN().toString());
            }
        } catch (KeyStoreException e) {
            MEN = "00";
            SIAException siae = new SIAException();
            siae.setErrorCode(OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION + MEN));
            SIALogger.println(this,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION + MEN));
            throw siae;
       }

    }

    /**
     *
     * @param rutaAlmacen Ruta al almacén donde se encuentran las claves.
     * @param tipusMagatzem Tipo de almacén al que se va acceder.
     * @param passAlmacen Contraseña de acceso al almacén.
     * @return Se devuelve el almacén de claves. (KeyStore)
     * @throws SIAException Excepción que se propaga en caso de error. Código de error y descripción.
     */
    public static KeyStore getMagatzemClaus(String rutaAlmacen, String tipusMagatzem, String passAlmacen) throws SIAException{
        String OPERACION  = HCCCSAML.OP_ALMACEN_CERTIFICADOS;
        String MEN;
        try {
            FileInputStream keyStoreIn = new FileInputStream(rutaAlmacen);
            KeyStore ks = KeyStore.getInstance(tipusMagatzem);
                            
            passAlmacen = DatatypeHelper.safeTrimOrNullString(passAlmacen);
            if (passAlmacen != null) {
                ks.load(keyStoreIn, passAlmacen.toCharArray());
                return ks;
            } else {                
                MEN = "06";
                SIAException siae = new SIAException();
                siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
                siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
                SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
                throw siae;
            }
        } catch (FileNotFoundException e) {
            MEN = "01";
            SIAException siae = new SIAException(e);
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        } catch (NoSuchAlgorithmException e) {
            MEN = "02";
            SIAException siae = new SIAException(e);
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        } catch (IOException e) {
            MEN = "03";
            SIAException siae = new SIAException(e);
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        } catch (CertificateException e) {
            MEN = "04";
            SIAException siae = new SIAException(e);
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        } catch (KeyStoreException e) {
            MEN = "00";
            SIAException siae = new SIAException(e);
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        }
    }

    /**
     * Método que devuelve el almacén de claves. (KeyStore)
     * @return Se devuelve el almacén de claves.
     */
    public KeyStore getMagatzemClaus(){
        return ALMACEN_CLAVES;
    }

    /**
     * Método que devuelve un certificado X509.
     * @return Se devuelve el certificado X509.
     */
    public X509Certificate getCertificate(){
        return X509;
    }

    /**
     * Método que devuelve la clave privada dado el almacén, el alias y la contraseña.
     * @param almacen Almacén de la que se quiere obtener la clave privada.
     * @param alias Alias del certificado que se quiere la clave privada.
     * @param passAlias 
     * @return
     * @throws SIAException Excepción que se propaga en caso de error. Código de error y descripción.
     */
    public static PrivateKey getClauPrivada(KeyStore almacen, String alias, String passAlias) throws SIAException{
        String OPERACION  = HCCCSAML.OP_ALMACEN_CERTIFICADOS;
        String MEN;

        alias = DatatypeHelper.safeTrimOrNullString(alias);
        if (alias == null) {
            MEN = "07";
            SIAException siae = new SIAException();
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        }

        passAlias = DatatypeHelper.safeTrimOrNullString(passAlias);
        if (passAlias == null) {
            MEN = "06";
            SIAException siae = new SIAException();
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        }

        try {
            return (PrivateKey) almacen.getKey(alias, passAlias.toCharArray());
        } catch (KeyStoreException e) {
            MEN = "00";
            SIAException siae = new SIAException(e);
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        } catch (NoSuchAlgorithmException e) {
            MEN = "02";
            SIAException siae = new SIAException(e);
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        } catch (UnrecoverableKeyException e) {
            MEN = "05";
            SIAException siae = new SIAException(e);
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        }
    }

    /**
     * Método que devuelve la clave privada del almacén de claves.
     * @return Clave privada de un certificado X509.
     * @throws SIAException Excepción que se propaga en caso de error. Código de error y descripción.
     */
    public PrivateKey getClauPrivada() throws SIAException{
        if(ALMACEN_CLAVES == null)
            ALMACEN_CLAVES = getMagatzemClaus();

        return getClauPrivada(ALMACEN_CLAVES,getAliasCert(),VALOR_PASSWORD_ALMACEN);
    }

    /**
     * Método que devuelve la clave pública de un certificado en el almacén de claves.
     * @param almacen Almacén de claves donde se encuentra el certificado del que se quiere la clave pública.
     * @param alias Alias del certificado en el almacén.
     * @return Clave pública del certificado.
     * @throws SIAException Excepción que se propaga en caso de error. Código de error y descripción.
     */
    public static PublicKey getClauPublica(KeyStore almacen,String alias) throws SIAException{
        String OPERACION  = HCCCSAML.OP_ALMACEN_CERTIFICADOS;
        String MEN;

        alias = DatatypeHelper.safeTrimOrNullString(alias);
        if (alias == null) {
            MEN = "07";
            SIAException siae = new SIAException();
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        }

        try {
            X509Certificate x509 = (X509Certificate)almacen.getCertificate(alias);            
            return x509.getPublicKey();
        } catch (KeyStoreException e) {
            MEN = "00";
            SIAException siae = new SIAException(e);
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(HCCCX509.class,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        }
    }

    /**
     * Método que devuelve la clave pública.
     * @return Clave pública del certificado.
     */
    public PublicKey getClauPublica(){        
        return X509.getPublicKey();
    }

    /**
     * Metodo que devuelve el alias del primer certificado X509 que se encuentre en el almacén de claves.
     * @return Devulve un String con el alias del certificado.
     * @throws SIAException Excepción que se propaga en caso de error. Código de error y descripción.
     */
    private String getAliasCert() throws SIAException{
        String OPERACION  = HCCCSAML.OP_ALMACEN_CERTIFICADOS;
        String MEN;

        String alias = "";
        try {

            Enumeration enume = ALMACEN_CLAVES.aliases();
            while(enume.hasMoreElements()){
                alias = (String)enume.nextElement();
                SIALogger.println(this,SIALogger.LEV_DEB,"Alias: " + alias);
                X509Certificate cert = (X509Certificate)ALMACEN_CLAVES.getCertificate(alias);
                //SIALogger.println(this,SIALogger.LEV_DEB,"Número de serie: " + Integer.toHexString(cert.getSerialNumber().intValue()));
                java.math.BigInteger SN = X509.getSerialNumber();
                String stSN1 = SN.toString(16);
                SIALogger.println(this,SIALogger.LEV_DEB,"Numero de serie cert: " + stSN1);                                
    						java.math.BigInteger bi = new java.math.BigInteger(VALOR_NUMERO_SERIE_CERT, 16);
    						String stSN2 = bi.toString(16);
    						SIALogger.println(this,SIALogger.LEV_DEB,"Numero de serie prop: " + stSN2);                
                SIALogger.println(this,SIALogger.LEV_DEB,"Tipo: " + cert.getType()); 
                if (stSN1.equals(stSN2))                
                    return alias;
            }
        } catch (KeyStoreException e) {
            MEN = "00";
            SIAException siae = new SIAException(e);
            siae.setErrorCode(HCCCSAML.VALOR_COD_MENSAJE_HCCSA + OPERACION + MEN);
            siae.setDescription(HCCCSAML.getMissatge(OPERACION,MEN));
            SIALogger.println(this,SIALogger.LEV_ERR, HCCCSAML.getMissatge(OPERACION,MEN));
            throw siae;
        }
        return "";
    }

    /**
     * Método que devuelve el DN de un certificado X509.
     * @return DN del certificado X509.
     */
    public String getDN(){
        return X509.getSubjectDN().toString();
    }
}
