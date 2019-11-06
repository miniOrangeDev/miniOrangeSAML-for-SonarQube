package com.miniorange.saml;

public class JavaScripts {
	
	private JavaScripts() {

	}
	
    public static final String disable_script ="<script src=\"https://code.jquery.com/jquery-1.10.2.js\">" +
            "window.onload = alert(\"Alert 1\");" +
            "$( \"input[name*='mo']\").prop(\"disabled\",true); " +
            "alert(\"Alert 2\");</script>";
}
