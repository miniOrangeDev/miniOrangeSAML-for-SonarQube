package com.miniorange.saml;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class Redirector {
    private static  HttpServletResponse response;
    
    public Redirector(HttpServletResponse r) {
    	Redirector.response = r;
    }
    
    public static HttpServletResponse getResponse()
    {
    	return response;
    	
    }
    
    public static void doRedirect() throws IOException {
        response.sendRedirect("https://www.google.com");
    }
}
