package com.miniorange.saml;

import org.sonar.api.Plugin;


public class MiniorangeSamlPlugin implements Plugin {


    @Override
    public void define(Context context) {
    	
    	// Start Point like main function
    	 context.addExtensions(MiniorangeSamlProperties.class,MiniorangeAuthProvider.class);
         context.addExtensions(
                 MiniorangeSamlProperties.definitions()
        );
    }
}
