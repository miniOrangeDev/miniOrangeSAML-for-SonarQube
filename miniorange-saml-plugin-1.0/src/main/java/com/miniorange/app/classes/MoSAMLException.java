package com.miniorange.app.classes;


public class MoSAMLException extends RuntimeException {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private final SAMLErrorCode errorCode;

	private final String message;

	private final String resolution;

	public MoSAMLException(SAMLErrorCode errorCode) {
		this.errorCode = errorCode;
		this.message = errorCode.getMessage();
		this.resolution = errorCode.getResolution();
	}

	public MoSAMLException(String message, String resolution, SAMLErrorCode errorCode) {
		this.errorCode = errorCode;
		this.message = message;
		this.resolution = resolution;
	}

	public MoSAMLException(Throwable cause, SAMLErrorCode errorCode) {
		super(cause);
		this.errorCode = errorCode;
		this.message = cause.getMessage();
		this.resolution = errorCode.getResolution();
	}

	public MoSAMLException(String message, SAMLErrorCode errorCode) {
		this.message = message;
		this.errorCode = errorCode;
		this.resolution = errorCode.getResolution();
	}
	
	@Override
	public String getMessage() {
		return message;
	}

	public String getResolution() { return resolution; }

	public SAMLErrorCode getErrorCode() {
		return errorCode;
	}

	public enum SAMLErrorCode {

		INVALID_ISSUER("Invalid Issuer in the SAML Response.", "Please verify IDP Entity ID value is correct."),

		INVALID_SIGNATURE(
				"Invalid Signature in the SAML Response. The certificate you provided did not match the signature in " +
						"SAML Response.", "Please verify the X.509 certificate is correct."),

		INVALID_DESTINATION("Invalid Destination in the SAML Response.", 
				"Make sure that Destination value is configured correctly on your IDP."),

		INVALID_RECIPIENT("Invalid Recipient in the SAML Response.", 
				"Make sure that Recipient value is configured correctly on your IDP."),

		INVALID_AUDIENCE("Invalid Audience in the SAML Response.", 
				"Make sure that Audience value is configured correctly on your IDP."),

		INVALID_CERTIFICATE("Invalid Certificate provided for validation. Incorrect certificate format.", 
				"Please provide the X.509 Certificate in the correct format."),

		RESPONSE_NOT_SIGNED("SAML Response not signed by your IdP.", "Make sure your IDP is signing at least SAML " +
				"Response or SAML Assertion."),

		ASSERTION_NOT_SIGNED("SAML Assertion not signed by your IdP.", "Make sure your IDP is signing at least SAML " +
				"Response or SAML Assertion."),

		INVALID_CONDITIONS("Invalid Conditions in the SAML Response.", "Make sure your Server time is in sync with " +
				"your IDP Server."),

		UNKNOWN("An unknown error occurred.", "Please check logs for the exact error and contact support for help."),

		INVALID_SAML_STATUS("Invalid SAML Status code.","The request could not be performed due to an error on the " +
				"part of the SAML responder or SAML authority. Make sure IdP returns SUCCESS status code in SAML " +
				"Response. Please unchecked the Send Signed Requests and try again"),

		RESPONDER("Invalid SAML Status code.","The request could not be performed due to an error on the part of the " +
				"SAML responder or SAML authority. Make sure IdP returns SUCCESS status code in SAML Response. Please " +
				"unchecked the Send Signed Requests in Configure IDP Tab and try again.");
		
		
		private String message;

		private String resolution;

		private SAMLErrorCode(String message, String resolution) {
			this.message = message;
			this.resolution = resolution;
		}

		public String getMessage() {
			return message;
		}

		public String getResolution() { 
			return resolution; 	
		}
	}
}
