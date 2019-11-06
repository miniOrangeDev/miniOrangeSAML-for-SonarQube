/*
 * SAML 2.0 Authentication for SonarQube
 * Copyright (C) 2018-2019 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

package com.miniorange.app.helpers;

import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;


public class MoSAMLSPMeta{
	
	public static final Logger log = Loggers.get(MoSAMLSPMeta.class);
	
	private MoSAMLSPMeta() {
		//		
	}

	public static void showMetadata(HttpServletResponse response, HttpServletRequest request){
	
		log.debug("Rendering Metadata ");
		
		MoSAMLSettings settings = new MoSAMLSettings();
		try {
			String metadata = IOUtils.toString(MoSAMLUtils.class.getResourceAsStream("/metadata-template.xml"), StandardCharsets.UTF_8);
			
			String certificate = settings.getPublicSPCertificate();
			certificate = MoSAMLUtils.deserializePublicCertificate(certificate);

			String spBaseURL = request.getRequestURL().toString().replace(request.getRequestURI(),"");
			String acsURL = spBaseURL + "/oauth2/callback/miniorangesamlplugin";
			String spEntityID = spBaseURL + "/sonar_saml_auth";

			settings.setSpEntityId(spEntityID);
			settings.setAcsUrl(acsURL);
			settings.setSpBaseUrl(spBaseURL);

			metadata = StringUtils.replace(metadata, "##SP_ENTITY_ID##", settings.getSpEntityId(), 1);
			metadata = StringUtils.replace(metadata, "##ACS_URL##", settings.getAcsUrl(), 1);
			metadata = StringUtils.replace(metadata, "##SIGNING_CERT##", certificate, 1);
			metadata = StringUtils.replace(metadata, "##ENCRYPTION_CERT##", certificate, 1);

			
			
			response.setContentType("text/html");
			PrintWriter out = response.getWriter();
			
			out.println("<!DOCTYPE html>"
						+"<html><head><title>SP Metadata</title>"
						+"<style type=\"text/css\">"
						
						+"textarea{ resize : none; }"
						
						+"body{ font-family : 'Helvetica Neue',Helvetica,Arial,sans-serif;"
						+"font-weight : bold; font-size : 14px; color : #444;"
						+"line-height : 1.42857143;}"
						
						+"label{ margin : 10px; }"
						
						//CSS for Text Fields
						+".txt-control {"
						+"color : #555;"
						+"margin : 10px;"
						+"width : 220px;"
						+"display : float;"
						+"font-size : 14px;"
					    +"padding : 2px 8px;"
					    +"border-radius : 4px;"
					    +"border : 1px solid #ccc;"
					    +"background-color : #fff;"
					    +"line-height : 1.42857143;"
					    +"}"
					    				    	
					    //CSS for buttons and links
					    +".btn, button, input[type=button], input[type=submit] {"
					    +"margin : 10px;"
					    +"height : 24px;"
					    +"outline : none;"
					    +"color : #236a97;"
					    +"cursor : pointer;"
					    +"font-size : 12px;"
					    +"padding : 0 12px;"
					    +"font-weight : 600;"
					    +"line-height : 22px;"
					    +"border-radius : 2px;"
					    +"text-align : center;"
					    +"text-decoration : none;"
					    +"display : inline-block;"
					    +"box-sizing : border-box;"
					    +"background : transparent;"
				        +"vertical-align : baseline;"
				        +"border : 1px solid #236a97;"
				        +"transition : border-color .2s ease;"
					    +"}"
				        
					    //button hover effect
					    +".btn:hover, button:hover, a:hover{"
					    + "color : white;"
					    + "background : #236a97;}"
					   
						+"</style>"
						+"</head>");
			
			out.println("<body>"
						+"<div padding='15px'>"
						+"<table align='center'><tr>"
							+"<td><label>SP Entity ID :</label></td>"
							+"<td><input type='button' class='btn' id='spidbtn' value='Copy' onclick=\"copyTextFunction('spidtxt','spidbtn')\"><br/></td>"
							+"<td><label> ACS URL :</label></td>"
							+"<td><input type='button' class='btn' id='acsbtn' value='Copy' onclick=\"copyTextFunction('acstxt','acsbtn')\"><br/></td>"
						+"</tr>");
							
			out.println("<tr><td colspan='2'><input type='text' class='txt-control' id='spidtxt' value='"+settings.getSpEntityId()+"' readonly><br/><br/></td>"
						+"<td colspan='2'><input type='text' class='txt-control' id='acstxt' value='"+settings.getAcsUrl()+"' readonly><br/><br/></td></tr>");
				
			
			out.println("<tr><td><label> Signing Certificate :</label></td>"
							+"<td><input type='button' class='btn' id='certbtn' value='Copy' onclick=\"copyTextFunction('certtxt','certbtn')\"></td>"
							+"<td><a class='btn' style=\"margin-left:20px;\" href='/sessions/init/miniorangesamlplugin?RelayState=download_certificate' download>Download Certificate</a><br/></td>"
						+ "</tr>");
			
			out.println("<tr><td colspan='4'><textarea id='certtxt' class='txt-control' style=\"width:480px\" rows='4' readonly>"+"-----BEGIN CERTIFICATE-----"+certificate+"-----END CERTIFICATE-----"
								+"</textarea></td></tr>");
			
			out.println("<tr><td><label> Encryption Certificate :</label></td>"
							+"<td><input type='button' class='btn' id='encertbtn' value='Copy' onclick=\"copyTextFunction('encerttxt','encertbtn')\"><br/></td>"
							+"<td><a class='btn' style=\"margin-left:20px;\" href='/sessions/init/miniorangesamlplugin?RelayState=download_certificate' download>Download Certificate</a></td>"
						+"</tr>");
			
			out.println("<tr><td colspan='4'><textarea id='encerttxt' class='txt-control' style=\"width:480px\" rows='4' readonly>"+"-----BEGIN CERTIFICATE-----"+certificate+"-----END CERTIFICATE-----"
							+"</textarea><br/><br/></td></tr>");
			
			out.println("<tr><td><label> Different Format </label></td>"
							+"<td><input type='radio' name='format' id='txt' onchange=\"alterHiddenFunction('txt','txtformat','fileformat')\">Text &nbsp&nbsp</td>"
							+"<td><input type='radio' name='format' id='file' onchange=\"alterHiddenFunction('file','fileformat','txtformat')\">File<br></td>"
						+ "</tr>");
			
									//hidden part for text meta data format
			out.println("<tr><td colspan='4' id='txtformat' hidden><label>Text Format</label>"
								+"<input type='button' class='btn' style=\"margin-left:95px;\" id='txtformatbtn' value='Copy' onclick=\"copyTextFunction('txtfrmtarea','txtformatbtn')\" ><br/>"
								+ "<textarea style='width:480px' class='txt-control' id='txtfrmtarea' rows='5' readonly>"+metadata+"</textarea>"
						+"</td></tr>");
					
									//hidden part for file meta data format
			out.println("<tr><td colspan='4' id='fileformat' hidden>"
							+"<center><a class='btn' target='_parent' href='/sessions/init/miniorangesamlplugin?RelayState=download_metadata' download> Download Metadata File</a>"
						+ "</center></td></tr>");	

			out.println("</table></div>"
						+"<script>"	
							//JS function to change buttons text
						+"function copyTextFunction(txtid, btnid) {"
						+"var copyText = document.getElementById(txtid);"
						+"copyText.select();"
						+"copyText.setSelectionRange(0, 99999);" //For mobile devices
						+"document.execCommand(\"copy\");"
						+"document.getElementById(btnid).value = \"Copied\";"
						+"}");
						
							//JS function to change hidden property of element
			out.println("function alterHiddenFunction(radioid,format1,format2){"
						+"var v = document.getElementById(radioid);"
						+"if(v.id==\"txt\"){"
						+	"document.getElementById(format1).hidden=false;"
						+	"document.getElementById(format2).hidden=true;}"
						+"else if(v.id==\"file\"){"
						+	"document.getElementById(format1).hidden=false;"
						+	"document.getElementById(format2).hidden=true;}"
						+ 	"v.scrollIntoView();"
						+"}");	
					
			out.println("</script></body></html>");
			
					} catch (Exception e) {
						log.error(e.getMessage());
					}
	}
	
	
	
	public static void downloadMetadata(HttpServletResponse response, HttpServletRequest request)
	{
		log.debug("Downloading Metadata in xml form");
		MoSAMLSettings settings = new MoSAMLSettings();
		try {
			String metadata = IOUtils.toString(MoSAMLUtils.class.getResourceAsStream("/metadata-template.xml"), StandardCharsets.UTF_8);
			String certificate = settings.getPublicSPCertificate();
			certificate = MoSAMLUtils.deserializePublicCertificate(certificate);

			String spBaseURL = request.getRequestURL().toString().replace(request.getRequestURI(),"");
			String acsURL = spBaseURL + "/oauth2/callback/miniorangesamlplugin";
			String spEntityID = spBaseURL + "/sonar_saml_auth";

			settings.setSpEntityId(spEntityID);
			settings.setAcsUrl(acsURL);
			settings.setSpBaseUrl(spBaseURL);

			metadata = StringUtils.replace(metadata, "##SP_ENTITY_ID##", settings.getSpEntityId(), 1);
			metadata = StringUtils.replace(metadata, "##ACS_URL##", settings.getAcsUrl(), 1);
			metadata = StringUtils.replace(metadata, "##SIGNING_CERT##", certificate, 1);
			metadata = StringUtils.replace(metadata, "##ENCRYPTION_CERT##", certificate, 1);

			response.setContentType("text/xml");
			response.getOutputStream().write(metadata.getBytes());
			
		} catch (Exception e) {
			log.error(e.getMessage());
		}		
		
		
	}
	
	public static void downloadCertificate(HttpServletResponse response)
	{
		log.debug("Downloading Certificate");
	
		try {																			
			String cert = IOUtils.toString(MoSAMLUtils.class.getResourceAsStream("/certificates/sp-certificate.crt"), StandardCharsets.UTF_8);
			response.setContentType("text/txt");
			response.getOutputStream().write(cert.getBytes());
			
		} catch (Exception e) {
			log.error(e.getMessage());
		}		
		
	}
	
	
}
