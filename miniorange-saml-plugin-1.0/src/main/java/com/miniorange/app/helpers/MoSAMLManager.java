package com.miniorange.app.helpers;

import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.io.Writer;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.lang3.StringUtils;
import org.apache.xml.security.signature.XMLSignature;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.validation.ValidationException;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.miniorange.app.classes.MoSAMLException;
import com.miniorange.app.classes.MoSAMLResponse;


public class MoSAMLManager {
	private String certificateexpected="";
	private String replacement="";
	private static Logger log = Loggers.get(MoSAMLManager.class);
	private static final String UTF_8 = "UTF-8";
	private static final String HTTPPOST = "HttpPost";
	
	
	//method for sending user auth'n request to IdP
	public void createAuthnRequestAndRedirect( HttpServletResponse response, String relayState,MoSAMLSettings settings) {
		try {
			log.debug("Creating Authentication Request and redirecting user to Idp for authentication");
			MoSAMLUtils.doBootstrap();		// enables security mechanism
			AuthnRequest authnRequest = MoSAMLUtils.buildAuthnRequest(settings.getSpEntityId(),
					settings.getAcsUrl(), settings.getSamlLoginUrl(), settings.getNameIDFormat(), settings.getForceAuthentication());
			
			if (StringUtils.equals(settings.getSamlLoginBindingType(), HTTPPOST)) {
				log.debug("HTTP-POST Binding selected for SSO");
				if (settings.isRequestSigned()) {
					authnRequest = (AuthnRequest) MoSAMLUtils.signHttpPostRequest(authnRequest,
							settings.getPublicSPCertificate(), settings.getPrivateSPCertificate());
				}
				//encoding request with base 64 encoding
				String encodedAuthnRequest = MoSAMLUtils.base64EncodeRequest(authnRequest, Boolean.valueOf(true));
				String form = createHttpPostRequestForm(settings.getSamlLoginUrl(), encodedAuthnRequest, relayState);
				response.setContentType("text/html");
				response.getOutputStream().write(form.getBytes(StandardCharsets.UTF_8));
				response.getOutputStream().close();
				
			} else {
				log.debug("HTTP-Redirect Binding selected for SSO");
				String encodedAuthnRequest = MoSAMLUtils.base64EncodeRequest(authnRequest, false);
				String urlForSignature = createRequestQueryParamsForSignature(encodedAuthnRequest, relayState);
				String signature = MoSAMLUtils.signHttpRedirectRequest(urlForSignature,
						XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, settings.getPublicSPCertificate(),
						settings.getPrivateSPCertificate());
				String redirectUrl;
				if (settings.isRequestSigned()) {
					redirectUrl = createRedirectURL(settings.getSamlLoginUrl(),encodedAuthnRequest, relayState,
							XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, signature, false);
				} else {
					redirectUrl = createUnSignedRedirectURL(settings.getSamlLoginUrl(), encodedAuthnRequest,
							relayState, false);

				}
				//***redirecting user
				httpRedirect(response, redirectUrl);
				
			}
		} catch (IOException e) {
			log.error(e.getMessage());
		} catch (Exception e) {
			log.error("An unknown error occurred while creating the AuthnRequest.", e);
			throw new MoSAMLException(MoSAMLException.SAMLErrorCode.UNKNOWN);
			
		}
	}
	
	
	public static void httpRedirect(HttpServletResponse response, String redirectUrl) throws IOException {
		log.debug("Redirecting user to " + redirectUrl);
		response.sendRedirect(redirectUrl);
	}
	
	public String getTestAuthnRequest(MoSAMLSettings settings) {
		try {
			log.debug("Creating Authentication Request.");
			MoSAMLUtils.doBootstrap();
			AuthnRequest authnRequest = MoSAMLUtils.buildAuthnRequest(settings.getSpBaseUrl(),
					settings.getAcsUrl(), settings.getSamlLoginUrl(), settings.getNameIDFormat(), 
					settings.getForceAuthentication());
			
			if (settings.isRequestSigned() && StringUtils.equals(settings.getSamlLoginBindingType(), HTTPPOST)){
				authnRequest = (AuthnRequest) MoSAMLUtils.signHttpPostRequest(authnRequest,
						settings.getPublicSPCertificate(), settings.getPrivateSPCertificate());
				
			}

			Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(authnRequest);
			Element authDOM = marshaller.marshall(authnRequest);
			Document doc = authDOM.getOwnerDocument();
			
			//***changes made setFeature() method added for security
			TransformerFactory factory = TransformerFactory.newInstance();
			factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
			Transformer transformer = factory.newTransformer();
			//***
			
			transformer.setOutputProperty(OutputKeys.ENCODING, UTF_8);
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			Writer out = new StringWriter();
			transformer.transform(new DOMSource(doc), new StreamResult(out));
			
			//***returning authentication request 
			return out.toString();

		} catch (Exception e) {
			log.error("An error occurred while creating the AuthnRequest.", e);
			throw new MoSAMLException(MoSAMLException.SAMLErrorCode.UNKNOWN);
		}
	}
	
	private String createRequestQueryParamsForSignature(String httpRedirectRequest, String relayState)
			throws UnsupportedEncodingException {
		log.debug("Creating request query parameter for signature");
		
		StringBuilder urlForSignature = new StringBuilder();
		urlForSignature.append(MoSAMLUtils.SAML_REQUEST_PARAM).append("=")
				.append(URLEncoder.encode(httpRedirectRequest, StandardCharsets.UTF_8.toString()));
		urlForSignature.append("&").append(MoSAMLUtils.RELAY_STATE_PARAM).append("=");
		if (StringUtils.isNotBlank(relayState)) {
			urlForSignature.append(URLEncoder.encode(relayState, StandardCharsets.UTF_8.toString()));
		} else {
			urlForSignature.append(URLEncoder.encode("/", StandardCharsets.UTF_8.toString()));
		}
		return urlForSignature.toString();
	}
	
	private String createResponseQueryParamsForSignature(String httpRedirectResponse, String relayState)
			throws UnsupportedEncodingException {
		log.debug("Creating response query parameter for signature");
		StringBuilder urlForSignature = new StringBuilder();
		urlForSignature.append(MoSAMLUtils.SAML_RESPONSE_PARAM).append("=")
				.append(URLEncoder.encode(httpRedirectResponse, StandardCharsets.UTF_8.toString()));
		urlForSignature.append("&").append(MoSAMLUtils.RELAY_STATE_PARAM).append("=");
		if (StringUtils.isNotBlank(relayState)) {
			urlForSignature.append(URLEncoder.encode(relayState, StandardCharsets.UTF_8.toString()));
		} else {
			urlForSignature.append(URLEncoder.encode("/", StandardCharsets.UTF_8.toString()));
		}
		return urlForSignature.toString();
	}
	
	private String createRedirectURL(String url, String samlRequestOrResponse, String relayState, String sigAlgo,
            String signature, Boolean isResponse) throws UnsupportedEncodingException {
		StringBuilder builder = new StringBuilder(url);
		if (StringUtils.contains(url, "?") && !(StringUtils.endsWith(url, "?") || StringUtils.endsWith(url, "&"))) {
			builder.append("&");
		} else if (!StringUtils.contains(url, "?")) {
			builder.append("?");
		}
		if (isResponse) {
			builder.append(createResponseQueryParamsForSignature(samlRequestOrResponse, relayState));
		} else {
			builder.append(createRequestQueryParamsForSignature(samlRequestOrResponse, relayState));
		}
		builder.append("&").append(MoSAMLUtils.SIGNATURE_ALGO_PARAM).append("=")
		.append(URLEncoder.encode(sigAlgo, UTF_8)).append("&").append(MoSAMLUtils.SIGNATURE_PARAM).append("=")
		.append(URLEncoder.encode(signature, UTF_8));
		return builder.toString();
	}
	
	private String createUnSignedRedirectURL(String url, String samlRequestOrResponse, String relayState,
            Boolean isResponse) throws UnsupportedEncodingException {
		StringBuilder builder = new StringBuilder(url);
		if (StringUtils.contains(url, "?") && !(StringUtils.endsWith(url, "?") || StringUtils.endsWith(url, "&"))) {
			builder.append("&");
		} else if (!StringUtils.contains(url, "?")) {
			builder.append("?");
		}
		if (isResponse) {
			builder.append(createResponseQueryParamsForSignature(samlRequestOrResponse, relayState));
		} else {
			builder.append(createRequestQueryParamsForSignature(samlRequestOrResponse, relayState));
		}
		return builder.toString();
	}
	
	private String createHttpPostRequestForm(String ssoUrl, String encodedRequest, String relayState) {
		StringBuilder form = new StringBuilder("<html><head>");
		form.append("<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/1.8.3/jquery.min.js\"></script>");
		form.append("<script type=\"text/javascript\">$(document).ready( function() { document");
		form.append(".forms['saml-request-form'].submit(); });</script></head>");
		form.append("<body>Please wait...<form action=\"" + ssoUrl +"\" method=\"post\" id=\"saml-request-form\">");
		form.append("<input type=\"hidden\" name=\"SAMLRequest\" value=\"" + MoSAMLUtils.htmlEncode(encodedRequest) + "\" />");
		form.append("<input type=\"hidden\" name=\"RelayState\" value=\"" + MoSAMLUtils.htmlEncode(relayState) + "\" />");
		form.append("</form></body></html>");
		
		return form.toString();
	}
	
	private String createHttpPostResponseForm(String ssoUrl, String encodedResponse, String relayState) {
		StringBuilder form = new StringBuilder("<html><head>");
		
		form.append("<script src=\"https://ajax.googleapis.com/ajax/libs/jquery/1.8.3/jquery.min.js\"></script>");
		form.append("<script type=\"text/javascript\">$(document).ready(function() { ");
		form.append("document.forms['saml-request-form'].submit(); });</script></head>");
		form.append("<body>Please wait...<form action=\"" + ssoUrl + "\" method=\"post\" id=\"saml-request-form\">");
		form.append("<input type=\"hidden\" name=\"MoSAMLResponse\" value=\"" + MoSAMLUtils.htmlEncode(encodedResponse) + "\" />");
		form.append("<input type=\"hidden\" name=\"RelayState\" value=\"" + MoSAMLUtils.htmlEncode(relayState) + "\" />");
		form.append("</form></body></html>");
		
		return form.toString();
	}

	
	
	public MoSAMLResponse readSAMLResponse(HttpServletRequest request, MoSAMLSettings settings) {
		try {
			log.debug("Reading SAML Response.");
			MoSAMLUtils.doBootstrap();
			String encodedSAMLResponse = request.getParameter(MoSAMLUtils.SAML_RESPONSE_PARAM);
			String relayState = request.getParameter(MoSAMLUtils.RELAY_STATE_PARAM);
			Response samlResponse = MoSAMLUtils.decodeResponse(encodedSAMLResponse);
			if (!StringUtils.equals(samlResponse.getStatus().getStatusCode().getValue(), StatusCode.SUCCESS_URI)) {
				log.error("Invalid SAML response. SAML Status Code received: "
						+ samlResponse.getStatus().getStatusCode().getValue());
				String message;
				if (samlResponse.getStatus().getStatusMessage() != null) {
					log.error("Saml Status Message received: " + samlResponse.getStatus().getStatusMessage().getMessage());
					message = samlResponse.getStatus().getStatusMessage().getMessage()
							+ ". Status Code received in SAML response: "
							+ samlResponse.getStatus().getStatusCode().getValue().split(":")[7];
				} else {
					message = "Invalid status code \""
							+ samlResponse.getStatus().getStatusCode().getValue().split(":")[7]
							+ "\" received in SAML response";
				}

				if(StringUtils.equalsIgnoreCase(samlResponse.getStatus().getStatusCode().getValue().split(":")[7], StatusCode.RESPONDER_URI)){
					log.error(message);
					throw new MoSAMLException(message, MoSAMLException.SAMLErrorCode.RESPONDER);
				}else{
					log.error(message);
					throw new MoSAMLException(message, MoSAMLException.SAMLErrorCode.INVALID_SAML_STATUS);
				}
			}
			Assertion assertion;
			
			//***use of isEmpty() method instead of size() for checking list isn't empty
			if(samlResponse.getAssertions() != null && !samlResponse.getAssertions().isEmpty()){
				assertion = samlResponse.getAssertions().get(0);
			} else {
				assertion = MoSAMLUtils.decryptAssertion(samlResponse.getEncryptedAssertions().get(0),
						settings.getPublicSPCertificate(), settings.getPrivateSPCertificate());
			}

			verifyConditions(assertion, settings.getSpEntityId());

			String acs = settings.getAcsUrl();
			String idpACS = acs+"?idp="+ "";
			verifyIssuer(samlResponse, assertion, settings.getIdpEntityId());
			verifyDestination(samlResponse, acs, idpACS);
			verifyRecipient(assertion, acs,idpACS);
			MoSAMLException t = null;
			Boolean verified = Boolean.FALSE;
			try {
				verified = verifyCertificate(samlResponse, assertion, settings.getX509Certificate());
			} catch (MoSAMLException e) {
				t = e;
			}/***
			List<String> certificates = idpConfig.getCertificates();
			if (certificates != null) {
				for (int index = 1; index < certificates.size(); index++) {
					try {
						verified = verifyCertificate(samlResponse, assertion, certificates.get(index));
					} catch (MoSAMLException e) {
						t = e;
					}
					if (verified)
						break;
				}
			}****/
			if (!verified && t!=null){
				log.error(t.getMessage(), t);
				throw t;					
			}
			Map<String, String[]> attributes = getAttributes(assertion);
			NameID nameId = assertion.getSubject().getNameID();
			String nameIdValue = StringUtils.EMPTY;
			String sessionIndex = assertion.getAuthnStatements().get(0).getSessionIndex();
			if (nameId != null) {
				nameIdValue = nameId.getValue();
			}
			attributes.put("NameID", new String[] { nameIdValue });
			
			return new MoSAMLResponse(attributes, nameIdValue, sessionIndex, relayState);
			
		} catch (MoSAMLException e) {
			log.error(e.getMessage(), e);
			throw e;
		} catch (Exception e) {
			log.error("An error occurred while verifying the SAML Response.", e);
			throw new MoSAMLException(e, MoSAMLException.SAMLErrorCode.UNKNOWN);
		}
	}
	
	public long timeInMiliseconds() {
		String time = "0";
		log.debug("Time is: " + time);
		
		long timeDelay = Long.parseLong(time);
		timeDelay = timeDelay * 60 * 1000;
		return timeDelay;
	}
	
	private void verifyConditions(Assertion assertion, String audienceExpected) {
		log.debug("Verifying Conditions...");
		long timediff;
		Date now = new DateTime().toDate();
		Date notBefore = null;
		Date notOnOrAfter = null;
		long timeDifferenceInBefore = 0;
		long timeDifferenceInAfter = 0;
		
		if (assertion.getConditions().getNotBefore() != null) {
			notBefore = assertion.getConditions().getNotBefore().toDate();
			if (now.before(notBefore))
				timeDifferenceInBefore = Math.abs(notBefore.getTime() - now.getTime());
			log.debug("timeDifferenceInBefore = " + timeDifferenceInBefore);
		}
		if (assertion.getConditions().getNotOnOrAfter() != null) {
			notOnOrAfter = assertion.getConditions().getNotOnOrAfter().toDate();
			if (now.after(notOnOrAfter))
				timeDifferenceInAfter = Math.abs(now.getTime() - notOnOrAfter.getTime());
			log.debug("timeDifferenceInAfter = " + timeDifferenceInAfter);
		}
		long userAddeddelay = timeInMiliseconds();
		long timediff1=userAddeddelay - timeDifferenceInBefore;
		log.debug("time difference :"+timediff1);
		
		long timediff2=userAddeddelay - timeDifferenceInAfter;

		if(timediff1!=0) {
			timediff=-timediff1;
			replacement="Forward";
		}
		else
		{
			timediff=-timediff2;
			replacement="Back";
		}
		long valueinminutes=((timediff/(60*1000))%60);
		long exactvalueinminutes=Math.incrementExact(valueinminutes);
		log.debug("time in miniseconds = " + timeInMiliseconds());
		log.debug("time diff before = " + (userAddeddelay - timeDifferenceInBefore));
		log.debug("time diff after = " + (userAddeddelay - timeDifferenceInAfter));
		
		if (notBefore != null && now.before(notBefore) && userAddeddelay - timeDifferenceInBefore < 0) {
			
			throwSamlException(exactvalueinminutes);
			
		}else if (notOnOrAfter != null && (now.after(notOnOrAfter) || now.equals(notOnOrAfter)) 
				&& userAddeddelay - timeDifferenceInAfter < 0) {
			
			throwSamlException(exactvalueinminutes);
		}

		List<Audience> audiencesInAssertion = assertion.getConditions().getAudienceRestrictions().get(0).getAudiences();
		Iterator<Audience> it = audiencesInAssertion.iterator();
		while (it.hasNext()) {
			Audience audience = it.next();
			if (StringUtils.equalsIgnoreCase(audience.getAudienceURI(), audienceExpected)) {
				return;
			}
		}
		MoSAMLException e = new MoSAMLException(MoSAMLException.SAMLErrorCode.INVALID_AUDIENCE);
		log.error(MoSAMLException.SAMLErrorCode.INVALID_AUDIENCE.getMessage(), e);
		throw e;
	}
	
	private void throwSamlException( long exactvalueinminutes)
	{
		MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_CONDITIONS;
		MoSAMLException samlexception = new MoSAMLException(errorCode.getMessage(),
				timeDiff(errorCode, exactvalueinminutes), errorCode);

		log.error(samlexception.getMessage(), samlexception);
		throw samlexception;
		
	}
	
	private String timeDiff(MoSAMLException.SAMLErrorCode error,long temp)
	{
		StringBuilder errorMsg = new StringBuilder(error.getResolution());
		errorMsg.append(" Set your Server clock "+replacement+" by ");
		errorMsg.append(temp);
		errorMsg.append(" minutes  Or you can Increase ");
		errorMsg.append(temp);
		errorMsg.append(" minutes in  validate Saml Response in SSO setting tab.");
		return errorMsg.toString();
	}
	
	private void verifyIssuer(Response response, Assertion assertion, String idpEntityId) {
		log.debug("Verifying Issuer in SAML Response");
		String issuerInResponse = response.getIssuer().getValue();
		String issuerInAssertion = assertion.getIssuer().getValue();
		if (!StringUtils.equals(issuerInResponse, idpEntityId)) {
			MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_ISSUER;
			MoSAMLException e = new MoSAMLException(errorCode.getMessage(),
					buildResolutionMessage(errorCode, idpEntityId, issuerInResponse), errorCode);
			log.error(e.getMessage(), e);
			throw e;
		}
		if (!StringUtils.equals(issuerInAssertion, idpEntityId)) {
			MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_ISSUER;
			MoSAMLException e = new MoSAMLException(errorCode.getMessage(),
					buildResolutionMessage(errorCode, idpEntityId, issuerInAssertion), errorCode);
			log.error(e.getMessage(), e);
			throw e;
		}
	}

	private void verifyDestination(Response response, String acsUrl, String idpAcsUrl) {
		// Destination is Optional field so verify only if exist.
		log.debug("Verifying Destination if present in SAML Response");
		String destInResponse = response.getDestination();
		if (StringUtils.isBlank(destInResponse) || StringUtils.equals(destInResponse, acsUrl) || StringUtils.equals(destInResponse,idpAcsUrl)) {
			return;
		}
		MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_DESTINATION;
		MoSAMLException e = new MoSAMLException(errorCode.getMessage(),
				buildResolutionMessage(errorCode, acsUrl, destInResponse), errorCode);
		log.error(e.getMessage(), e);
		throw e;
	}

	private void verifyRecipient(Assertion assertion, String acsUrl, String idpAcsUrl) {
		log.debug("Verifying Recipient if present in SAML Response");
		String recipientInResponse = assertion.getSubject().getSubjectConfirmations().get(0)
				.getSubjectConfirmationData().getRecipient();
		if (StringUtils.isBlank(recipientInResponse) || StringUtils.equals(recipientInResponse, acsUrl) || StringUtils.equals(recipientInResponse,idpAcsUrl)) {
			return;
		}
		MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_RECIPIENT;
		MoSAMLException e = new MoSAMLException(errorCode.getMessage(),
				buildResolutionMessage(errorCode, acsUrl, recipientInResponse), errorCode);
		log.error(e.getMessage(), e);
		throw e;
	}
	
	private String buildResolutionMessage(MoSAMLException.SAMLErrorCode error, String found, String expected) {
		StringBuilder errorMsg = new StringBuilder(error.getResolution());
		errorMsg.append(" Connector was expecting ");
		errorMsg.append(expected);
		errorMsg.append(" but found: ");
		errorMsg.append(found);
		return errorMsg.toString();
	}
	
	private Boolean verifyCertificate(Response response, Assertion assertion, String x509Certificate) {
		log.debug("Verifying Certificates.");
		if(x509Certificate!=null)
			try {
				if (!response.isSigned() && !assertion.isSigned()) {
					MoSAMLException e = new MoSAMLException(MoSAMLException.SAMLErrorCode.ASSERTION_NOT_SIGNED);
					log.error(MoSAMLException.SAMLErrorCode.ASSERTION_NOT_SIGNED.getMessage(), e);
					throw e;
				}
				if (response.isSigned()) {
					return MoSAMLUtils.verifyCertificate(response, x509Certificate);
				}
				if (assertion.isSigned()) {
					return MoSAMLUtils.verifyCertificate(assertion, x509Certificate);
				}
				log.error("Error occured while verifing the certificate");
			} catch (CertificateException|NoSuchAlgorithmException e) {
				MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_CERTIFICATE;
				MoSAMLException samlexception = new MoSAMLException(errorCode.getMessage(),
                    buildResolutionforcertificate(errorCode,assertion,response), errorCode);

				log.error(samlexception.getMessage(), e);
				throw samlexception;
			} catch (ValidationException e) {
				MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_SIGNATURE;
	            MoSAMLException samlexception = new MoSAMLException(errorCode.getMessage(),
	                    buildResolutionforcertificate(errorCode,assertion,response), errorCode);
	            
	            log.error(samlexception.getMessage(), e);
	            throw samlexception;
			} catch (InvalidKeySpecException e) {
				MoSAMLException.SAMLErrorCode errorCode = MoSAMLException.SAMLErrorCode.INVALID_CERTIFICATE;
	            MoSAMLException samlexception = new MoSAMLException(errorCode.getMessage(),
	                    buildResolutionforcertificate(errorCode,assertion,response), errorCode);
	
	            log.error(samlexception.getMessage(), e);
	            throw samlexception;
			}
		return false;
	}
	
	private String buildResolutionforcertificate(MoSAMLException.SAMLErrorCode error,Assertion assertion,Response response)
	{

		if(assertion.isSigned() ) {
			List<X509Data> x509Datas = assertion.getSignature().getKeyInfo().getX509Datas();
			for (X509Data x509Data : x509Datas) {
				List<X509Certificate> certificates = x509Data.getX509Certificates();

				for (X509Certificate certificate : certificates) {
					certificateexpected = certificate.getValue();

				}
			}
		}
		else if(response.isSigned()) {
			List<X509Data> x509Datas = response.getSignature().getKeyInfo().getX509Datas();
			for (X509Data x509Data : x509Datas) {
				List<X509Certificate> certificates = x509Data.getX509Certificates();

				for (X509Certificate certificate : certificates) {
					certificateexpected = certificate.getValue();
				}
			}
		}
		StringBuilder errorMsg = new StringBuilder(error.getResolution());
		errorMsg.append(" Expected certificate : ");
		errorMsg.append(
				"<textarea rows='6' cols='100' word-wrap='break-word;' style='width:580px; margin:0px; " +
						"height:290px;' id ='errormsg' readonly>-----BEGIN CERTIFICATE-----"+ certificateexpected + "-----END CERTIFICATE-----</textarea> ");


		return errorMsg.toString();
	}
	
	public void createLogoutRequestAndRedirect( HttpServletResponse response, String nameId,
			String sessionIndex, String relayState, MoSAMLSettings settings) {
		try {
			log.debug("Creating LogoutRequest. Relay State is: " + relayState);
			MoSAMLUtils.doBootstrap();
			LogoutRequest logoutRequest = MoSAMLUtils.buildLogoutRequest(settings.getSpEntityId(),
					settings.getSamlLogoutUrl(), nameId, sessionIndex);

			// Checking SLO binding type to send request
			if (StringUtils.equals(settings.getSloBindingType(), HTTPPOST)) {
				log.debug("HTTP-POST Binding selected for SLO");
				
				if (settings.isRequestSigned()) {
					logoutRequest = (LogoutRequest) MoSAMLUtils.signHttpPostRequest(logoutRequest,
							settings.getPublicSPCertificate(), settings.getPrivateSPCertificate());
				}
				String encodedLogoutRequest = MoSAMLUtils.base64EncodeRequest(logoutRequest, true);
				String form = createHttpPostRequestForm(settings.getSamlLogoutUrl(), encodedLogoutRequest, relayState);
				response.getOutputStream().write(form.getBytes());
				response.getOutputStream().close();
				
			} else {
				log.debug("HTTP-Redirect Binding selected for SLO");
				String encodedLogoutRequest = MoSAMLUtils.base64EncodeRequest(logoutRequest, false);
				String urlForSignature = createRequestQueryParamsForSignature(encodedLogoutRequest, relayState);
				String signature = MoSAMLUtils.signHttpRedirectRequest(urlForSignature,
						XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, settings.getPublicSPCertificate(),
						settings.getPrivateSPCertificate());
				String redirectUrl;
				
				if (settings.isRequestSigned()) {
					redirectUrl = createRedirectURL(settings.getSamlLogoutUrl(), encodedLogoutRequest, relayState,
							XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, signature, false);
				} else {
					redirectUrl = createUnSignedRedirectURL(settings.getSamlLogoutUrl(), encodedLogoutRequest,
							relayState, false);
				}
				
				log.debug("Redirect URL is..." + redirectUrl);
				httpRedirect(response, redirectUrl);
				
			}
		} catch (Exception e) {
			log.error("An unknown error occurred while creating the LogoutRequest.", e);
			throw new MoSAMLException(MoSAMLException.SAMLErrorCode.UNKNOWN);
		}
	}
	
	public void createLogoutResponseAndRedirect(HttpServletRequest request, HttpServletResponse response,
			Boolean isPostRequest, MoSAMLSettings settings) {
		try {
			log.debug("Creating Logout Response.");
			MoSAMLUtils.doBootstrap();
			String relayState = StringUtils.isNotBlank(settings.getCustomLogoutURL()) ? settings.getCustomLogoutURL()
					: request.getParameter("RelayState");
			String logoutRequestStr = request.getParameter("SAMLRequest");
			LogoutRequest logoutRequest = MoSAMLUtils.readLogoutRequest(logoutRequestStr, isPostRequest);
			LogoutResponse logoutResponse = MoSAMLUtils.buildLogoutResponse(settings.getSpEntityId(),
					settings.getSamlLogoutUrl(), logoutRequest.getID(), StatusCode.SUCCESS_URI);

			// Checking SLO binding type to send response
			if (StringUtils.equals(settings.getSloBindingType(), HTTPPOST)) {
				log.debug("HTTP-POST Binding selected for SLO");
				if (settings.isRequestSigned()) {
					logoutResponse = (LogoutResponse) MoSAMLUtils.signHttpPostRequest(logoutResponse,
							settings.getPublicSPCertificate(), settings.getPrivateSPCertificate());
				}
				String encodedLogoutResponse = MoSAMLUtils.base64EncodeRequest(logoutResponse, true);
				String form = createHttpPostResponseForm(settings.getSamlLogoutUrl(), encodedLogoutResponse,
						relayState);
				response.getOutputStream().write(form.getBytes());
				response.getOutputStream().close();
				
			} else {
				log.debug("HTTP-Redirect Binding selected for SLO");
				String encodedLogoutResponse = MoSAMLUtils.base64EncodeRequest(logoutResponse, false);
				String urlForSignature = createResponseQueryParamsForSignature(encodedLogoutResponse,
						request.getParameter("RelayState"));
				String signature = MoSAMLUtils.signHttpRedirectRequest(urlForSignature,
						XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, settings.getPublicSPCertificate(),
						settings.getPrivateSPCertificate());
				String redirectUrl;
				if (settings.isRequestSigned()) {
					redirectUrl = createRedirectURL(settings.getSamlLogoutUrl(), encodedLogoutResponse, relayState,
							XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256, signature, true);
				} else {
					redirectUrl = createUnSignedRedirectURL(settings.getSamlLogoutUrl(), encodedLogoutResponse,
							relayState, true);
				}
				httpRedirect(response, redirectUrl);
			}
		} catch (Exception e) {
			log.error("An unknown error occurred while creating the LogoutRequest.", e);
			throw new MoSAMLException(MoSAMLException.SAMLErrorCode.UNKNOWN);
		}
	}
	
	private Map<String, String[]> getAttributes(Assertion assertion) {
		log.debug("Getting attributes from SAML Response");
		Map<String, String[]> attributes = new HashMap<>();
		
		if (!assertion.getAttributeStatements().isEmpty()) {
			for (Attribute attr : assertion.getAttributeStatements().get(0).getAttributes()) {
				if (!attr.getAttributeValues().isEmpty()) {
					String[] values = new String[attr.getAttributeValues().size()];
					for (int i = 0; i < attr.getAttributeValues().size(); i++) {
						values[i] = attr.getAttributeValues().get(i).getDOM().getTextContent();
					}
					attributes.put(attr.getName(), values);
				}
			}
		}
		return attributes;
	}

}
