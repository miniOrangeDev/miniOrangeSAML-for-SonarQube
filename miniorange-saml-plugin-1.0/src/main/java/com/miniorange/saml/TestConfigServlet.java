package com.miniorange.saml;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.sonar.api.utils.log.Logger;
import org.sonar.api.utils.log.Loggers;

import com.miniorange.app.classes.MoSAMLException;
import com.miniorange.app.classes.MoSAMLResponse;
import com.miniorange.app.helpers.MoSAMLManager;
import com.miniorange.app.helpers.MoSAMLSettings;

@WebServlet
public class TestConfigServlet extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

    private static Logger log = Loggers.get(TestConfigServlet.class);
    

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
        MoSAMLResponse samlResponse = null;
        MoSAMLManager manager = new MoSAMLManager();
        MoSAMLSettings settings = new MoSAMLSettings();
        MoSAMLException exception = null;
        try { 
        	samlResponse = manager.readSAMLResponse(request, settings); 
        	
        } catch (MoSAMLException e) {
        	exception = e;
        }
        
        try{
        	TestConfigServlet.showTestConfigurationResult(samlResponse, response, exception);
        }catch(IOException e){
        	log.error(e.getMessage());
        }
    }
    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
    	try{
    		log.debug("doPost() called, redirecting to doGet()");
    		doGet(request, response);	
    	}catch(IOException e){
    		log.error(e.getMessage());
    		
    	}
       
    }
    public static void showTestConfigurationResult(MoSAMLResponse moSAMLResponse, HttpServletResponse response, MoSAMLException e) throws IOException {
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
                    .append("<div style=\"margin:3%;display:block;text-align:center;\"><input style=\"padding:1%;"
                            + "width:100px;background: #0091CD none repeat scroll 0% 0%;cursor: pointer;font-size:15px;"
                            + "border-width: 1px;border-style: solid;border-radius: 3px;white-space: nowrap;"
                            + "box-sizing:border-box;border-color: #0073AA;box-shadow:0px 1px 0px rgba(120,200,230,0.6) inset;"
                            + "color: #FFF;\" type=\"button\" value=\"Done\" onClick=\"self.close();\"></div>");
            response.setCharacterEncoding("iso-8859-1");
            response.setContentType("text/html");
            response.getOutputStream().write(htmlStart.toString().getBytes(StandardCharsets.UTF_8));
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
            response.setCharacterEncoding("iso-8859-1");
            response.setContentType("text/html");
            response.getOutputStream().write(htmlStart.toString().getBytes(StandardCharsets.UTF_8));
        }
        log.debug("Output render complete");
       

    }
}
