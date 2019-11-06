package com.miniorange.app.helpers;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

import com.miniorange.saml.MiniorangeSamlProperties;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

public class MoSAMLSettings {
    private final String CUSTOMER_TOKEN_KEY = generateRandomAlphaNumericKey(16);
    
    private static final String PUBLIC_CERT_PATH = "/certificates/sp-certificate.crt";
    private static final String PRIVATE_CERT_PATH = "/certificates/sp-key.key";
    private static final String CONFIG_FILE_PATH = "/config.properties";
    
    private static String publicCertificate;
    private static String privateCertificate;
   
    static Properties properties = new Properties();
    private static Logger log = Loggers.get(MoSAMLSettings.class);
    

    static {
        try {
            publicCertificate = IOUtils.toString(MoSAMLSettings.class.getResourceAsStream(PUBLIC_CERT_PATH), StandardCharsets.UTF_8);
            publicCertificate = MoSAMLUtils.serializePublicCertificate(publicCertificate);

            privateCertificate = IOUtils.toString(MoSAMLSettings.class.getResourceAsStream(PRIVATE_CERT_PATH), StandardCharsets.UTF_8);
            privateCertificate = MoSAMLUtils.serializePrivateCertificate(privateCertificate);

            properties.load(MoSAMLSettings.class.getResourceAsStream(CONFIG_FILE_PATH));
        } catch (IOException e) {
            log.error("An I/O error occurred while initializing the SAML Settings.", e);
        }
    }

    public Boolean isEnabled() {
        if (MiniorangeSamlProperties.getConfigurtaion() == null) {
            log.debug("config is null");
        }
        Boolean value = MiniorangeSamlProperties.getConfigurtaion().getBoolean(MiniorangeSamlProperties.ENABLE).orElse(false);
        log.debug("miniOrangeSAML Auth enabled : " + value);
        return value;
    }

    public Boolean allowSignUp() {
        Boolean value = MiniorangeSamlProperties.getConfigurtaion().getBoolean(MiniorangeSamlProperties.SIGN_UP).orElse(false);
        log.debug("Allow Sign Up : " + value);
        return value;
    }

    public String getIdpName() {
        String value = MiniorangeSamlProperties.getConfigurtaion().get(MiniorangeSamlProperties.IDP_NAME).orElse("Undefined Name");
        log.debug("Getting IDP NAME : " + value);
        return value;
    }

    public String getIdpEntityId() {
        String value = MiniorangeSamlProperties.getConfigurtaion().get(MiniorangeSamlProperties.IDP_ISSUER).orElse("IDP ISSUER MISSING");
        log.debug("Getting IDP ISSUER : " + value);
        return value;
    }

    public Boolean isRequestSigned() {
        Boolean value = MiniorangeSamlProperties.getConfigurtaion().getBoolean(MiniorangeSamlProperties.SIGN_REQUEST).orElse(false);
        log.debug("Is REQUEST SIGNED : " + value);
        return value;
    }

    public String getSamlLoginUrl() {
        String value = MiniorangeSamlProperties.getConfigurtaion().get(MiniorangeSamlProperties.LOGIN_URL).orElse("LOGIN URL MISSING");
        log.debug("Getting LOGIN URL : " + value);
        return value;
    }

    public String getSamlLoginBindingType() {
        String value = MiniorangeSamlProperties.getConfigurtaion().get(MiniorangeSamlProperties.BIND_TYPE).orElse("DEFAULT BIND TYPE");
        log.debug("Getting BIND TYPE : " + value);
        return value;
    }


    public String getX509Certificate() {
        String value = MiniorangeSamlProperties.getConfigurtaion().get(MiniorangeSamlProperties.X509).orElse("EMPTY OR INVALID CERTIFICATE");
        log.debug("Getting X509 CERTIFICATE : " + value);
        return value;
    }

    public String getNameIDFormat() {
        return properties.getProperty("nameIDFormat");
    }

    public String getSpBaseUrl() {
        return properties.getProperty("spBaseUrl");
    }

    public String getSpEntityId() {
        return properties.getProperty("spEntityId");
    }

    public String getAcsUrl() {
        return properties.getProperty("acsUrl");
    }

    public String getLoginAttr() {
        String value = MiniorangeSamlProperties.getConfigurtaion().get(MiniorangeSamlProperties.LOGIN_ATTR).orElse("EMPTY LOGIN ATTRIBUTE");
        log.debug("Getting LOGIN ATTRIBUTE : " + value);
        return value;
    }

    public String getEmailAttr() {
        String value = MiniorangeSamlProperties.getConfigurtaion().get(MiniorangeSamlProperties.EMAIL_ATTR).orElse("EMPTY EMAIL ATTRIBUTE");
        log.debug("Getting EMAIL ATTRIBUTE : " + value);
        return value;
    }

    public String getNameAttr() {
        String value = MiniorangeSamlProperties.getConfigurtaion().get(MiniorangeSamlProperties.NAME_ATTR).orElse("EMPTY NAME ATTRIBUTE");
        log.debug("Getting NAME ATTRIBUTE : " + value);
        return value;
    }

    public String getGroupAttr() {
        String value = MiniorangeSamlProperties.getConfigurtaion().get(MiniorangeSamlProperties.GROUP_ATTR).orElse("EMPTY GROUP ATTRIBUTE");
        log.debug("Getting GROUP ATTRIBUTE : " + value);
        return value;
    }

    public Boolean isAutoRedirectEnabled() {
        Boolean value = MiniorangeSamlProperties.getConfigurtaion().getBoolean(MiniorangeSamlProperties.AUTO_REDIRECT).orElse(false);
        log.debug("Is AUTO-REDIRECT ENABLED : " + value);
        return value;
    }

    public Boolean getForceAuthentication() {
        Boolean value = MiniorangeSamlProperties.getConfigurtaion().getBoolean(MiniorangeSamlProperties.FORCE_AUTHN).orElse(false);
        log.debug("Is FORCE AUTHN ENABLED : " + value);
        return value;
    }

    public String getPublicSPCertificate() {
        return publicCertificate;
    }

    public String getPrivateSPCertificate() {
        return privateCertificate;
    }

    public String getSamlLogoutUrl() {
        return properties.getProperty("samlLogoutUrl");
    }

    public String getSloBindingType() {
        return "";
    }

    public String getCustomLogoutURL() {
        return "";
    }

    public String getApplicationUrl() {
        return properties.getProperty("applicationUrl");
    }

    public String getSAMLHandlerUrl() {
        return properties.getProperty("SAMLHandlerUrl");
    }

    public String getBase64EncodedKey() {
        return properties.getProperty("jwtKey");
    }

    public String getCustomerTokenKey() {
        return StringUtils.defaultString(this.CUSTOMER_TOKEN_KEY);
    }

    public void setSpBaseUrl(String value) {
        properties.setProperty("spBaseUrl", value);

    }

    public void setAcsUrl(String value) {
    	properties.setProperty("acsUrl", value);

    }

    public void setSpEntityId(String value) {
    	properties.setProperty("spEntityId", value);
    }

    public static String generateRandomAlphaNumericKey(int bytes) {
        return RandomStringUtils.random(bytes, true, true);
    }
}

