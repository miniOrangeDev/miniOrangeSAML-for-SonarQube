package com.miniorange.saml;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import org.sonar.api.server.ServerSide;
import org.sonar.api.server.authentication.Display;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import com.miniorange.app.classes.MoSAMLException;
import com.miniorange.app.classes.MoSAMLResponse;
import com.miniorange.app.helpers.MoSAMLManager;
import com.miniorange.app.helpers.MoSAMLSPMeta;
import com.miniorange.app.helpers.MoSAMLSettings;
import com.miniorange.app.helpers.MoSAMLUtils;


@ServerSide
public class MiniorangeAuthProvider implements OAuth2IdentityProvider {

	private static final String RELAYSTATE = "RelayState";
    private final MoSAMLSettings settings = new MoSAMLSettings();
    private static Logger log = Loggers.get(MiniorangeAuthProvider.class);
    
    @SuppressWarnings("unused")
	private static MiniorangeSamlProperties property;
    
   

    public MiniorangeAuthProvider(MiniorangeSamlProperties property) {
        MiniorangeAuthProvider.property = property;
    }

    @Override
    public String getKey() {
        return "miniorangesamlplugin";
    }

    @Override
    public String getName() {
        return "SAML IDP";
    }

    //this is button appeard at login time
    @Override
    public Display getDisplay() {
        return Display.builder()
                // URL of src/main/resources/static/saml.png at runtime
                .setIconPath("/static/miniorangesamlplugin/icon.png")
                .setBackgroundColor("#444444")
                .build();
    }

    @Override
    public boolean isEnabled() {
        return settings.isEnabled();
    }

    @Override
    public boolean allowsUsersToSignUp() {
        return settings.allowSignUp();
    }

    @Override
    public void init(InitContext context) {
        
        MoSAMLManager manager = new MoSAMLManager();
        String relayState = settings.getSpBaseUrl();
        log.debug("Checking for relay state");
        if (context.getRequest().getParameterMap().containsKey(RELAYSTATE)) {
            log.debug("Relay state present...");
            
            if (context.getRequest().getParameter(RELAYSTATE).equals("testconfig")) {
                log.debug("Setting test relay state...");
                relayState = context.getRequest().getParameter(RELAYSTATE);
            }
            
            if (context.getRequest().getParameter(RELAYSTATE).equals("show_result")) {
                try {
                    MoSAMLUtils.testDisplay(context.getResponse(), context.getRequest());
                    return;
                } catch (IOException e) {
                	log.error(e.getMessage());
                }
            }
            
            if (context.getRequest().getParameter(RELAYSTATE).equals("show_metadata")) {
                MoSAMLSPMeta.showMetadata(context.getResponse(), context.getRequest());
                return;
            }
            if (context.getRequest().getParameter(RELAYSTATE).equals("download_metadata")) {
                MoSAMLSPMeta.downloadMetadata(context.getResponse(), context.getRequest());
                return;
            }
            if (context.getRequest().getParameter(RELAYSTATE).equals("download_certificate")) {
                MoSAMLSPMeta.downloadCertificate(context.getResponse());
                return;
            }
        }
        
        manager.createAuthnRequestAndRedirect( context.getResponse(), relayState, settings);
    }

    @Override
    public void callback(CallbackContext callbackContext) {
        
        MoSAMLManager manager = new MoSAMLManager();
        MoSAMLException exception = null ;
        MoSAMLResponse samlResponse = null ;
        
        log.debug("Reading response...");
        samlResponse = manager.readSAMLResponse(callbackContext.getRequest(), settings);
       
        log.debug("Checking relay state...");
        String relaystate = callbackContext.getRequest().getParameter(RELAYSTATE);
        
        log.debug("RelayState : " + relaystate);
        
        if (callbackContext.getRequest().getParameterMap().containsKey(RELAYSTATE) && Objects.equals(callbackContext.getRequest().getParameter(RELAYSTATE), "testconfig")) {
            log.debug("Test relay state found. Processing output...");
            try {
	                String output = MoSAMLUtils.showTestConfigurationResult(samlResponse, exception);
	                //***changed deprecated URLEncoder.encode("string") to URLEncoder.encode("string","encode_type");
	                callbackContext.getResponse().sendRedirect("/sessions/init/miniorangesamlplugin?RelayState=show_result&output=" + URLEncoder.encode(output,"UTF-8"));
	                return;
            	
            } catch (IOException e) {
                log.debug(e.getMessage());
            }
        }
 
        
        Map<String, String[]> attributes = samlResponse.getAttributes();

        UserIdentity.Builder userIdentityBuilder = UserIdentity.builder()
                .setLogin(getValue(attributes, settings.getLoginAttr()))
                .setProviderLogin(getValue(attributes, settings.getLoginAttr()))
                .setName(getValue(attributes, settings.getNameAttr()));
        String emailAttr = settings.getEmailAttr();
        if (emailAttr != null) {
            userIdentityBuilder.setEmail(getValue(attributes, emailAttr));
        }
        
      //*** Group Mapping
        String groupAttr = settings.getGroupAttr();
        log.debug("Group Attribute "+groupAttr);
        
        if (!groupAttr.equals("EMPTY GROUP ATTRIBUTE")) {
        	userIdentityBuilder.setGroups(getGroupSet(attributes, groupAttr));	
        }
        callbackContext.authenticate(userIdentityBuilder.build());
        callbackContext.redirectToRequestedPage();
    }

    String getValue(Map<String, String[]> attributes, String key) {
        String[] keyArray = new String[10];
        if (attributes.containsKey(key)) {
            keyArray = attributes.get(key);
        }
        return keyArray[0];
    }

    Set<String> getGroupSet(Map<String, String[]> attributes, String key) {
       
        Set<String> set = null;
        if (attributes.containsKey(key)) {
            set = new HashSet<>(Arrays.asList((String[]) attributes.get(key)));
        }
        return set;
    }
    
    
  
    
}
