package com.miniorange.app.helpers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterOutputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import com.google.gson.Gson;
import com.miniorange.app.classes.MoSAMLException;
import com.miniorange.app.classes.MoSAMLResponse;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


public class MoSAMLUtils {
	public static final String SAML_REQUEST_PARAM = "SAMLRequest";
	public static final String RELAY_STATE_PARAM = "RelayState";
	public static final String SIGNATURE_ALGO_PARAM = "SigAlg";
	public static final String SIGNATURE_PARAM = "Signature";
	public static final String SAML_RESPONSE_PARAM = "SAMLResponse";
	public static final Logger log = Loggers.get(MoSAMLUtils.class);
	
	private static final String NAMESPACE_PREFIX = "samlp";

	private static boolean bootstrap = false;
	
	private MoSAMLUtils() {
		//hiding implicit constructor
	}

	public static void doBootstrap() {
		if (!bootstrap) {
			try { log.debug("Setting bootstrap enabled");
				bootstrap = true;
				DefaultBootstrap.bootstrap();
			} catch (ConfigurationException e) {
				log.error(e.getMessage());
			}
		}
	}
	
	public static AuthnRequest buildAuthnRequest(String issuer, String acsUrl, String destination, String nameIdFormat, Boolean forceAuthn) {
		
		log.debug("Building Authentication Request");
				AuthnRequest authnRequest = new AuthnRequestBuilder().buildObject(SAMLConstants.SAML20P_NS,
				AuthnRequest.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
		DateTime issueInstant = new DateTime();
		authnRequest.setID(generateRandomString());
		authnRequest.setVersion(SAMLVersion.VERSION_20);
		authnRequest.setIssueInstant(issueInstant);
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		authnRequest.setIssuer(buildIssuer(issuer));
		authnRequest.setAssertionConsumerServiceURL(acsUrl);
		authnRequest.setDestination(destination);
		authnRequest.setForceAuthn(forceAuthn);
		//Create NameIDPolicy
	    NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
	    NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
	    nameIdPolicy.setFormat(nameIdFormat);
	    nameIdPolicy.setAllowCreate(true);
	    authnRequest.setNameIDPolicy(nameIdPolicy);
		return authnRequest;
	}
	
	public static SignableSAMLObject signHttpPostRequest(SignableSAMLObject request, String pubicKey, String privateKey) 
			throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, SecurityException, MarshallingException, SignatureException
			 {
		log.debug("Signing HTTP Post Request. ");
		
		
			org.opensaml.xml.signature.Signature signature = (org.opensaml.xml.signature.Signature) Configuration
					.getBuilderFactory().getBuilder(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME)
					.buildObject(org.opensaml.xml.signature.Signature.DEFAULT_ELEMENT_NAME);

			// Pass certificate type to get credentials
			Credential credential = getCredential(pubicKey, privateKey);

			signature.setSigningCredential(credential);
			signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			KeyInfoGeneratorManager keyInfoGeneratorManager = Configuration.getGlobalSecurityConfiguration()
					.getKeyInfoGeneratorManager().getDefaultManager();
			KeyInfoGeneratorFactory keyInfoGeneratorFactory = keyInfoGeneratorManager.getFactory(credential);
			KeyInfo keyInfo = keyInfoGeneratorFactory.newInstance().generate(credential);

			signature.setKeyInfo(keyInfo);
			String signatureAlgo = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
			signature.setSignatureAlgorithm(signatureAlgo);

			request.setSignature(signature);

			// Marshaling signableXmlObject
			MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();
			Marshaller marshaller = marshallerFactory.getMarshaller(request);
			marshaller.marshall(request);

			// Signing signableXmlObject
			Signer.signObject(signature);

			return request;

		/*
		 * org.opensaml.xmlsec.signature.Signature signature =
		 * OpenSAMLUtil.buildSignature(); Credential credential =
		 * getCredential(pubicKey, privateKey);
		 * signature.setSigningCredential(getCredential(pubicKey, privateKey));
		 * signature.setSignatureAlgorithm(XMLSignature.
		 * ALGO_ID_SIGNATURE_RSA_SHA256);
		 * signature.setCanonicalizationAlgorithm(Canonicalizer.
		 * ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		 * signature.setSigningCredential(credential);
		 * signature.setCanonicalizationAlgorithm(SignatureConstants.
		 * ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		 * 
		 * X509KeyInfoGeneratorFactory kiFactory = new
		 * X509KeyInfoGeneratorFactory();
		 * kiFactory.setEmitEntityCertificate(true);
		 * 
		 * try { KeyInfo keyInfo = kiFactory.newInstance().generate(credential);
		 * signature.setKeyInfo(keyInfo); } catch
		 * (org.opensaml.security.SecurityException ex) { throw ex; }
		 * 
		 * String signatureAlgo =
		 * SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
		 * signature.setSignatureAlgorithm(signatureAlgo);
		 * request.setSignature(signature); request.releaseDOM();
		 * request.releaseChildrenDOM(true); return request;
		 */
	
		
	}
	
	public static String signHttpRedirectRequest(String requestQueryString, String sigAlgo, String pubicKey,
			String privateKey) throws UnsupportedEncodingException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, InvalidKeyException, java.security.SignatureException  {
		log.debug("Signig Http Redirect Request called ");
		String signatureBase64encodedString = "";
			StringBuilder builder = new StringBuilder(requestQueryString);
			builder.append("&").append(SIGNATURE_ALGO_PARAM).append("=").append(URLEncoder.encode(sigAlgo, "UTF-8"));
			Signature signature = Signature.getInstance("SHA256withRSA");
			Credential credentials = getCredential(pubicKey, privateKey);
			signature.initSign(credentials.getPrivateKey());
			signature.update(builder.toString().getBytes());
			byte[] signatureByteArray = signature.sign();
			signatureBase64encodedString = Base64.encodeBytes(signatureByteArray);
			

		return signatureBase64encodedString;
	}
	
	
	public static String base64EncodeRequest(XMLObject request, Boolean isHttpPostBinding) throws MarshallingException, IOException  {
		log.debug("Encoding Sign Request with Base64 encoder.");
		String encodedRequestMessage = "";
			Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(request);
			Element authDOM = marshaller.marshall(request);

			// DOM to string
			StringWriter requestWriter = new StringWriter();
			XMLHelper.writeNode(authDOM, requestWriter);
			String requestMessage = requestWriter.toString();

			if (isHttpPostBinding) {
				return Base64.encodeBytes(requestMessage.getBytes(StandardCharsets.UTF_8), Base64.DONT_BREAK_LINES);
			}
			// compressing
			Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
			deflaterOutputStream.write(requestMessage.getBytes(StandardCharsets.UTF_8));
			deflaterOutputStream.close();
			byteArrayOutputStream.close();
			encodedRequestMessage = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);
			return encodedRequestMessage;
	}
	

	private static Credential getCredential(String publicKey, String privateKeyStr)
			throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
		
		publicKey = serializePublicCertificate(publicKey);
		InputStream is = new ByteArrayInputStream(publicKey.getBytes());
		CertificateFactory cf = CertificateFactory.getInstance("X509");
		java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate) cf.generateCertificate(is);
		BasicX509Credential x509Credential = new BasicX509Credential();
		x509Credential.setPublicKey(cert.getPublicKey());
		PrivateKey privateKey = getPrivateKey(privateKeyStr);
		if (privateKey != null) {
			x509Credential.setPrivateKey(privateKey);
		}
		Credential credential = x509Credential;
		log.debug("credential = " + credential);
		return credential;
	}
	
	private static Issuer buildIssuer(String issuerValue) {
		log.debug("Building Issuer");
		Issuer issuer = new IssuerBuilder().buildObject(SAMLConstants.SAML20_NS, Issuer.DEFAULT_ELEMENT_LOCAL_NAME,
				"saml");
		issuer.setValue(issuerValue);
		return issuer;
	}
	
	public static String generateRandomString() {
		String uuid = UUID.randomUUID().toString();
		return "_" + StringUtils.remove(uuid, '-');
	}
	
	public static String serializePublicCertificate(String certificate) {
		log.debug("Serializing Public Certificate");
		
		String BEGIN_CERTIFICATE = "BEGIN CERTIFICATE";
		String END_CERTIFICATE = "END CERTIFICATE";
		if (StringUtils.isNotBlank(certificate)) {
			certificate = StringUtils.remove(certificate, "\r");
			certificate = StringUtils.remove(certificate, "\n");
			certificate = StringUtils.remove(certificate, "-");
			certificate = StringUtils.remove(certificate, BEGIN_CERTIFICATE);
			certificate = StringUtils.remove(certificate, END_CERTIFICATE);
			certificate = StringUtils.remove(certificate, " ");
			
			org.apache.commons.codec.binary.Base64 encoder = new org.apache.commons.codec.binary.Base64(64);
			
			certificate = encoder.encodeToString(org.apache.commons.codec.binary.Base64.decodeBase64(certificate));
			StringBuilder cert = new StringBuilder("-----" + BEGIN_CERTIFICATE + "-----\r\n");
			cert.append(certificate);
			cert.append("-----" + END_CERTIFICATE + "-----");
			return cert.toString();
		}
		return certificate;
	}
	
	public static String serializePrivateCertificate(String certificate) {
		log.debug("Serializing Private Certificate");
		String BEGIN_CERTIFICATE = "BEGIN PRIVATE KEY";
		String END_CERTIFICATE = "END PRIVATE KEY";
		if (StringUtils.isNotBlank(certificate)) {
			certificate = StringUtils.remove(certificate, "\r");
			certificate = StringUtils.remove(certificate, "\n");
			certificate = StringUtils.remove(certificate, "-");
			certificate = StringUtils.remove(certificate, BEGIN_CERTIFICATE);
			certificate = StringUtils.remove(certificate, END_CERTIFICATE);
			certificate = StringUtils.remove(certificate, " ");
			org.apache.commons.codec.binary.Base64 encoder = new org.apache.commons.codec.binary.Base64(64);
			certificate = encoder.encodeToString(org.apache.commons.codec.binary.Base64.decodeBase64(certificate));
			StringBuilder cert = new StringBuilder("-----" + BEGIN_CERTIFICATE + "-----\r\n");
			cert.append(certificate);
			cert.append("-----" + END_CERTIFICATE + "-----");
			return cert.toString();
		}
		return certificate;
	}
	
	public static String deserializePublicCertificate(String certificate) {
		log.debug("Deserializing Public Certificate");
		String BEGIN_CERTIFICATE = "BEGIN CERTIFICATE";
		String END_CERTIFICATE = "END CERTIFICATE";
		if (StringUtils.isNotBlank(certificate)) {
			certificate = StringUtils.remove(certificate, "\r");
			certificate = StringUtils.remove(certificate, "\n");
			certificate = StringUtils.remove(certificate, "-");
			certificate = StringUtils.remove(certificate, BEGIN_CERTIFICATE);
			certificate = StringUtils.remove(certificate, END_CERTIFICATE);
			certificate = StringUtils.remove(certificate, " ");
		}
		return certificate;
	}
	
	public static String deserializePrivateCertificate(String certificate) {
		log.debug("Deserializing Private Certificate");
		String BEGIN_CERTIFICATE = "BEGIN PRIVATE KEY";
		String END_CERTIFICATE = "END PRIVATE KEY";
		if (StringUtils.isNotBlank(certificate)) {
			certificate = StringUtils.remove(certificate, "\r");
			certificate = StringUtils.remove(certificate, "\n");
			certificate = StringUtils.remove(certificate, "-");
			certificate = StringUtils.remove(certificate, BEGIN_CERTIFICATE);
			certificate = StringUtils.remove(certificate, END_CERTIFICATE);
			certificate = StringUtils.remove(certificate, " ");
		}
		return certificate;
	}
	
	private static PrivateKey getPrivateKey(String privateKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		log.debug("getPrivateKey called ");
		if (StringUtils.isNotBlank(privateKey)) {
			privateKey = deserializePrivateCertificate(privateKey);
			byte[] bytes = Base64.decode(privateKey);
			PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			return kf.generatePrivate(spec);
		}
		return null;
	}
	
	public static String htmlEncode(String s) {
		if (StringUtils.isNotBlank(s)) {
			StringBuilder encodedString = new StringBuilder("");
			char[] chars = s.toCharArray();
			for (char c : chars) {
				if (c == '<') {
					encodedString.append("&lt;");
				} else if (c == '>') {
					encodedString.append("&gt;");
				} else if (c == '\'') {
					encodedString.append("&apos;");
				} else if (c == '"') {
					encodedString.append("&quot;");
				} else if (c == '&') {
					encodedString.append("&amp;");
				} else {
					encodedString.append(c);
				}
			}
			return encodedString.toString();
		}
		return StringUtils.EMPTY;
	}
	
	public static String showTestConfigurationResult(MoSAMLResponse moSAMLResponse, MoSAMLException e) {
		log.debug("showTestConfigurationResult called.");
		if (e == null) {
			String username = "";
			StringBuilder htmlStart = new StringBuilder("<div style=\"font-family:Calibri;padding:0 3%;\">");
		
			htmlStart = htmlStart.append("<div style=\"color: #3c763d;background-color: #dff0d8; padding:2%;"
						+ "margin-bottom:20px;text-align:center; border:1px solid #AEDB9A; font-size:18pt;\">TEST "
						+ "SUCCESSFUL</div>");
			Iterator<String> iter = moSAMLResponse.getAttributes().keySet().iterator();

			while (iter.hasNext()) {
				String key = iter.next();
				if(key.equalsIgnoreCase("nameid")) {
					String[] values = moSAMLResponse.getAttributes().get(key);
					username = values[0];
				}
			}
			htmlStart = htmlStart.append("<span style=\"font-size:14pt;\"><b>Hello</b>, " + username + "</span><br/>"
					+ "<p style=\"font-weight:bold;font-size:14pt;margin-left:1%;\">ATTRIBUTES RECEIVED:</p>"
					+ "<table style=\"border-collapse:collapse;border-spacing:0; display:table;width:100%; "
					+ "font-size:14pt;background-color:#EDEDED;\"><tr style=\"text-align:center;\">"
					+ "<td style=\"font-weight:bold;border:2px solid #949090;padding:2%;\">ATTRIBUTE IDP_NAME</td>"
					+ "<td style=\"font-weight:bold;padding:2%;border:2px solid #949090; word-wrap:break-word;\">"
					+ "ATTRIBUTE VALUE</td></tr>");
			Iterator<String> it = moSAMLResponse.getAttributes().keySet().iterator();
			while (it.hasNext()) {
				String key = it.next();
				htmlStart = htmlStart.append("<tr><td style=\"font-weight:bold;border:2px solid #949090;padding:2%;\">"
						+ key + "</td><td style=\"padding:2%;border:2px solid #949090;word-wrap:break-word;\">");

				String[] values = moSAMLResponse.getAttributes().get(key);
				htmlStart = htmlStart.append(StringUtils.join(values, "<hr/>"));
				htmlStart = htmlStart.append("</td></tr>");
			}
			htmlStart = htmlStart.append("</table></div>");
			htmlStart = htmlStart
					.append("<div style=\"margin:3%;display:block;text-align:center;\">"
							+"</div>");
			return htmlStart.toString();
		} else {
			StringBuilder htmlStart = new StringBuilder("<div style=\"font-family:Calibri;padding:0 3%;\">");
			htmlStart = htmlStart
					.append("<div style=\"color:#a94442;background-color:#f2dede;padding:15px;margin-bottom:20px;"
							+ "text-align:center;border:1px solid #E6B3B2;font-size:18pt;\">TEST FAILED</div>");
			htmlStart = htmlStart
					.append("<table style=\"border-collapse:collapse;border-spacing:0; display:table;width:100%;"
							+ "font-size:14pt;\"><tr style=\"padding-top:10px;padding-bottom:10px;\"><td style=\"font-weight:bold;"
							+ "padding:10px 5px 10px 5px;\">Error Code</td><td style=\"word-wrap:break-word;\">"
							+ e.getErrorCode()
							+ "</td></tr><tr><td style=\"font-weight:bold;padding:10px 5px 10px 5px;\">"
							+ "Error Message</td><td style=\"word-wrap:break-word;\">" + e.getMessage()
							+ "</td></tr><tr>"
							+ "<td style=\"font-weight:bold;padding:10px 5px 10px 5px;\">Resolution</td>"
							+ "<td style=\"word-wrap:break-word;\">" + e.getResolution() + "</tr></table></div>");

			return htmlStart.toString();
		}

	}
	
	public static Response decodeResponse(String encodedResponse) 
			throws ParserConfigurationException, SAXException, IOException, UnmarshallingException  {
		log.debug("Decoding Response..");
		String xml = new String(Base64.decode(encodedResponse), StandardCharsets.UTF_8);
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		
		documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		documentBuilderFactory.setExpandEntityReferences(false);
		documentBuilderFactory.setNamespaceAware(true);
		
		DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
		ByteArrayInputStream is = new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8));
		Document document = docBuilder.parse(is);
		Element element = document.getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		XMLObject xmlObj = unmarshaller.unmarshall(element);
		return (Response) xmlObj;
	}
	
	public static Assertion decryptAssertion(EncryptedAssertion encryptedAssertion, String publicKey, String privateKey)
			throws CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, DecryptionException {
		log.debug("Decrypting Assertion.");
		StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(
				getCredential(publicKey, privateKey));
		Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
		Iterator<EncryptedKey> it = decrypter.getEncryptedKeyResolver().resolve(encryptedAssertion.getEncryptedData())
				.iterator();
		if (!it.hasNext()) {
			decrypter = new Decrypter(null, keyInfoCredentialResolver, new EncryptedElementTypeEncryptedKeyResolver());
		}
		decrypter.setRootInNewDocument(true);
		return decrypter.decrypt(encryptedAssertion);
	}
	
	public static Boolean verifyCertificate(SignableXMLObject response, String certificate)
			throws ValidationException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException {
		log.debug("Varifing Certificate");
		if (response.isSigned()) {
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			profileValidator.validate(response.getSignature());
			Credential verificationCredential = getCredential(certificate, "");
			SignatureValidator sigValidator = new SignatureValidator(verificationCredential);
			sigValidator.validate(response.getSignature());
			return Boolean.TRUE;
		} else {
			if (response instanceof Response) {
				log.error("Response not Signed");
				throw new MoSAMLException(MoSAMLException.SAMLErrorCode.RESPONSE_NOT_SIGNED);
			} else {
				log.error("Assertion not Signed");
				throw new MoSAMLException(MoSAMLException.SAMLErrorCode.ASSERTION_NOT_SIGNED);
			}
		}
	}
	
	public static LogoutRequest buildLogoutRequest(String issuer, String destination, String nameId,
			String sessionIndex) {
		log.debug("Building Logout Request");
		LogoutRequest logoutRequest = new LogoutRequestBuilder().buildObject(SAMLConstants.SAML20P_NS,
				LogoutRequest.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
		DateTime issueInstant = new DateTime();
		logoutRequest.setIssueInstant(issueInstant);
		logoutRequest.setID(generateRandomString());
		logoutRequest.setVersion(SAMLVersion.VERSION_20);
		logoutRequest.setIssuer(buildIssuer(issuer));
		logoutRequest.setDestination(destination);

		NameID nameIdObj = new NameIDBuilder().buildObject(SAMLConstants.SAML20_NS, NameID.DEFAULT_ELEMENT_LOCAL_NAME,"saml");
		nameIdObj.setSPNameQualifier(issuer);
		nameIdObj.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
		nameIdObj.setValue(nameId);
		logoutRequest.setNameID(nameIdObj);

		SessionIndex sessionIndexObj = new SessionIndexBuilder().buildObject(SAMLConstants.SAML20P_NS,
				SessionIndex.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
		sessionIndexObj.setSessionIndex(sessionIndex);
		sessionIndexObj.setSessionIndex(sessionIndex);
		logoutRequest.getSessionIndexes().add(sessionIndexObj);

		return logoutRequest;
	}
	
	public static LogoutResponse buildLogoutResponse(String issuer, String destination, String inResponseTo,
			String status) {
		log.debug("Building Logout Response");
		LogoutResponse logoutResponse = new LogoutResponseBuilder().buildObject(SAMLConstants.SAML20P_NS,
				LogoutResponse.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
		DateTime issueInstant = new DateTime();
		logoutResponse.setIssueInstant(issueInstant);
		logoutResponse.setID(generateRandomString());
		logoutResponse.setVersion(SAMLVersion.VERSION_20);
		logoutResponse.setIssuer(buildIssuer(issuer));
		logoutResponse.setDestination(destination);
		logoutResponse.setInResponseTo(inResponseTo);
		logoutResponse.setStatus(buildStatus(status));
		
		return logoutResponse;
	}
	
	public static LogoutRequest readLogoutRequest(String logoutRequestStr, Boolean isPostBinding)
			throws ParserConfigurationException, IOException, SAXException, UnmarshallingException {
		log.debug("Reading Logout Request");
		byte[] base64Decoded = org.opensaml.xml.util.Base64.decode(logoutRequestStr);
		String requestXml = new String(base64Decoded, StandardCharsets.UTF_8);
		if (!isPostBinding) {
			Inflater inflater = new Inflater(true);
			ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
			InflaterOutputStream inflaterOutputStream = new InflaterOutputStream(byteArrayOutputStream, inflater);
			inflaterOutputStream.write(base64Decoded);
			inflaterOutputStream.close();
			byteArrayOutputStream.close();
			requestXml = byteArrayOutputStream.toString();
		}
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

		documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
		documentBuilderFactory.setExpandEntityReferences(false);
		documentBuilderFactory.setNamespaceAware(true);
		
		DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
		ByteArrayInputStream is = new ByteArrayInputStream(requestXml.getBytes());
		Document document = docBuilder.parse(is);
		Element element = document.getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
		XMLObject xmlObj = unmarshaller.unmarshall(element);
		
		return (LogoutRequest) xmlObj;
	}
	
	private static Status buildStatus(String statusCodeValue) {
		log.debug("Building Status");
		StatusCode statusCode = new StatusCodeBuilder().buildObject(SAMLConstants.SAML20P_NS,
				StatusCode.DEFAULT_ELEMENT_LOCAL_NAME, NAMESPACE_PREFIX);
		statusCode.setValue(statusCodeValue);
		Status status = new StatusBuilder().buildObject(SAMLConstants.SAML20P_NS, Status.DEFAULT_ELEMENT_LOCAL_NAME,
				NAMESPACE_PREFIX);
		status.setStatusCode(statusCode);
		
		return status;
	}
	
	public static String getIdAsJwt(MoSAMLResponse samlResponse, String id, String issuer, long ttlMillis, String key) {
		HashMap<String, String> idMap = new HashMap<>();
		idMap.put("NameID", samlResponse.getNameId());
		idMap.put("SessionIndex", samlResponse.getSessionIndex());
		Gson gson = new Gson();
		String idJson = gson.toJson(idMap);
		
		return generateJWT(id, issuer, idJson, ttlMillis, key);
	}
	
	public static String getAttributesAsJwt(MoSAMLResponse samlResponse, String id, String issuer, long ttlMillis, String key) {
		HashMap<String, String[]> attributeMap = new HashMap<>();
		
		Iterator<String> iter = samlResponse.getAttributes().keySet().iterator();
		while(iter.hasNext()) {
			String attrKey = iter.next();
			String[] values = samlResponse.getAttributes().get(attrKey);
			
			attributeMap.put(attrKey, values);
		}
		Gson gson = new Gson();
		String attrJson = gson.toJson(attributeMap);
		
		return generateJWT(id, issuer, attrJson, ttlMillis, key);
	}
	
	@SuppressWarnings("deprecation")
	public static String generateJWT(String id, String issuer, String subject, long ttlMillis, String key) {
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
		long nowMillis = System.currentTimeMillis();
		Date now = new Date(nowMillis);
		String base64EncodedKey = key;
		
		
		JwtBuilder builder = Jwts.builder().setId(id)
										.setIssuer(issuer)
										.setIssuedAt(now)
										.setSubject(subject)
										.signWith(signatureAlgorithm, base64EncodedKey);
		
		if(ttlMillis >= 0) {
			long expMillis = nowMillis + ttlMillis;
			Date exp = new Date(expMillis);
			builder.setExpiration(exp);
		}
		
		return builder.compact();
	}
	
	public static String parseJWT(String jwt){
		
		String base64SecretBytes = "1DC5BC952855A614F30376298E74ADBDFEB1722745D4365465D652AB1EBBAD46";

		Claims claims = Jwts.parser()         
	    	       .setSigningKey(base64SecretBytes)
	    	       .parseClaimsJws(jwt).getBody();	    
	    return claims.getSubject();
	    
	}
	public static void testDisplay(HttpServletResponse response, HttpServletRequest request) throws IOException{
		String string = request.getParameter("output");
		response.setCharacterEncoding("iso-8859-1");
		response.setContentType("text/html");
		String decoded = decoder(string);
		response.getOutputStream().write(decoded.getBytes(StandardCharsets.UTF_8));
		
	}
	 static String decoder(String data) {
		try {
			data = data.replaceAll("%(?![0-9a-fA-F]{2})", "%25");
			data = data.replaceAll("\\+", "%2B");
			data = URLDecoder.decode(data, StandardCharsets.UTF_8.toString());
		} catch (Exception e) {
			log.error(e.getMessage());
		}
		return data;
	}
	
}
