package com.miniorange.saml;

import org.sonar.api.PropertyType;
import org.sonar.api.config.Configuration;

import org.sonar.api.config.PropertyDefinition;

import org.sonar.api.server.ServerSide;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;


import java.util.Arrays;
import java.util.List;


import static java.lang.String.valueOf;

@ServerSide
public class MiniorangeSamlProperties {
    public static final String ENABLE = "mo.saml.enable";
    public static final String SIGN_UP = "mo.saml.sign_up";

    public static final String LOGIN_URL = "mo.saml.login_url";
    public static final String IDP_ISSUER = "mo.saml.idp_issuer";
    public static final String X509 = "mo.saml.idp_x509";
    public static final String IDP_NAME = "mo.saml.idp_name";
    public static final String BIND_TYPE = "mo.saml.bind_type";
    public static final String SIGN_REQUEST = "mo.saml.sign_request";
    public static final String LOGIN_ATTR = "mo.saml.login_attr";
    public static final String EMAIL_ATTR = "mo.saml.email_attr";
    public static final String NAME_ATTR = "mo.saml.name_attr";
    public static final String GROUP_ATTR = "mo.saml.group_attr";
    public static final String FORCE_AUTHN = "mo.saml.force_authn";
    public static final String AUTO_REDIRECT = "mo.saml.auto_redirect";

    public static final String SP_BASE_URL = "mo.saml.sp_base";
    public static final String ACS_URL = "mo.saml.acs";
    public static final String SP_ENTITY_ID = "mo.saml.sp_entity";

    public static final String CATEGORY = "miniOrangeSAML";
    public static final String SUBCATEGORY = "miniOrange SAML Authentication";

    public static final String SP_META_BUTTON = "<br><a target=\"_blank\" href=\"/sessions/init/miniorangesamlplugin?RelayState=show_metadata\" class=\"button\" onclick=\"window.open(this.href, 'spdata','left=20,top=20,width=580,height=500,toolbar=0,resizable=0'); return false;\" >Show SP Metadata</a>";
    public static final String X509_BUTTONS = "<br><a target=\"_blank\" class=\"button\" style=\"margin-bottom:5px\" href='/sessions/init/miniorangesamlplugin?RelayState=testconfig' onclick=\"window.open(this.href, 'mywin',\n" +
            "'left=20,top=20,width=500,height=500,toolbar=1,resizable=0'); return false;\">Test Configuration</a><br>";
    public static final String CONTACT_US = "<br><a class=\"button\" target=\"_blank\" href=\"https://www.miniorange.com/contact\">Contact Us</a>";

    public static final String DEFAULT_LOGIN_ATTRIBUTE = "NameID";
    private static Configuration config;


    
    
    
    public MiniorangeSamlProperties(Configuration configuration) {
        Logger log = Loggers.get(MiniorangeSamlProperties.class);
        if(configuration == null){
            log.debug("config is null");
        }
        else{
            log.debug("config is not null");
        }
        config = configuration;
        
    }
    public static Configuration getConfigurtaion()
    {
    	return MiniorangeSamlProperties.config;
    }

    public static List<PropertyDefinition> definitions() {

        return Arrays.asList(
                PropertyDefinition.builder(MiniorangeSamlProperties.ENABLE)
                        .name("Enable SAML Login")
                        .description("Enable SAML SSO Authentication for Users." + SP_META_BUTTON)
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.BOOLEAN)
                        .defaultValue(valueOf(false))
                        .index(1)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.SIGN_UP)
                        .name("Allow Sign Up")
                        .description("Allow users to sign up if their account doesn't already exist, using SSO Authentication with your IdP")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.BOOLEAN)
                        .defaultValue(valueOf(false))
                        .index(2)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.IDP_NAME)
                        .name("IdP Name")
                        .description("Name of your IdP")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.STRING)
                        .index(3)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.IDP_ISSUER)
                        .name("IdP Entity ID")
                        .description(required("Issuer ID provided by the IdP"))
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.STRING)
                        .index(4)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.LOGIN_URL)
                        .name("Login URL")
                        .description(required("SAML Login URL of the IdP where the SAML request is sent."))
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.STRING)
                        .index(5)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.X509)
                        .name("x509 Certificate")
                        .description(required("x509 Certificate provided by IdP to verify response from it.") + X509_BUTTONS)
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.TEXT)
                        .index(6)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.LOGIN_ATTR)
                        .name("Login Attribute")
                        .description(required("Name of attribute in SAML response to be used as login credential."))
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.STRING)
                        .defaultValue(DEFAULT_LOGIN_ATTRIBUTE)
                        .index(7)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.NAME_ATTR)
                        .name("Name Attribute")
                        .description(required("Name of attribute in SAML response to be used as name credential."))
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.STRING)
                        .defaultValue(DEFAULT_LOGIN_ATTRIBUTE)
                        .index(8)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.EMAIL_ATTR)
                        .name("Email Attribute")
                        .description("Name of attribute in SAML response to be used as email credential.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.STRING)
                        .index(9)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.GROUP_ATTR)
                        .name("Group Attribute")
                        .description("Name of attribute in SAML response to be used as group alloted.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.STRING)
                        .index(10)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.FORCE_AUTHN)
                        .name("Force Authentication")
                        .description("Force Authentication at IdP every time.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.BOOLEAN)
                        .defaultValue(valueOf(false))
                        .index(11)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.SIGN_REQUEST)
                        .name("Sign Request")
                        .description("Sign the SAML request with a private key.")
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.BOOLEAN)
                        .defaultValue(valueOf(false))
                        .index(12)
                        .build(),
                PropertyDefinition.builder(MiniorangeSamlProperties.BIND_TYPE)
                        .name("Login Binding Type")
                        .description("Method used for sending SAML request." + CONTACT_US)
                        .category(CATEGORY)
                        .subCategory(SUBCATEGORY)
                        .type(PropertyType.SINGLE_SELECT_LIST)
                        .options("HttpRedirect", "HttpPost")
                        .defaultValue("HttpRedirect")
                        .index(13)
                        .build()


        );
    }

    static String required(String input) {
        input = input.concat("<span style=\"color:red\">*</span>");
        return input;
    }
}
