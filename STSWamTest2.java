package test;

import com.pingidentity.sts.clientapi.STSClient;
import com.pingidentity.sts.clientapi.STSClientConfiguration;
import com.pingidentity.sts.clientapi.model.RequestSecurityTokenData;
import com.pingidentity.sts.clientapi.model.STSResponse;
import com.pingidentity.sts.clientapi.tokens.saml.Saml20Token;
import com.pingidentity.sts.clientapi.tokens.saml.Saml20TokenHandler;
import com.pingidentity.sts.clientapi.tokens.wsse.UsernameToken;
import com.pingidentity.sts.clientapi.utils.StringUtils;

import org.apache.commons.codec.binary.Base64;

import java.io.StringReader;
import java.security.cert.X509Certificate;
import javax.net.ssl.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;


public class STSWamTest {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		STSWamTest.disableSSLVerification();

		String b64saml = "<long string of base64 encoded SAML>"
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		try {

			String samlstring = new String(Base64.decodeBase64(b64saml), "UTF-8");
			System.out.println("decoded: " + samlstring);
			
			DocumentBuilder samlBuilder = dbf.newDocumentBuilder();
			Document samltext = samlBuilder.parse(new InputSource(new StringReader(samlstring)));
			Saml20Token samlToken = new Saml20Token(samltext.getDocumentElement());

			String wamToken = STSWamTest.getWamToken(samlToken.getRoot());
			System.out.println("wam token: " + wamToken);
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public STSWamTest(){}

	/*
	 * Uses the STSClient object to exchange a SAML token for a binary WAM token
	 */
	@SuppressWarnings("finally")
	public static Element getSamlToken(){

		STSClientConfiguration	stsIdpClientConfig = new STSClientConfiguration();     
		Element samlStsToken = null;

		stsIdpClientConfig.setStsEndpoint("https://localhost:9031/idp/sts.wst");
		stsIdpClientConfig.setIgnoreSSLTrustErrors(true);

		StringUtils utils = new StringUtils();

		try {

			//Generates a username RST and requests the wam token. Currently the wam token type is not included the TokenType enum.
			RequestSecurityTokenData rst = new RequestSecurityTokenData();
			rst.setAppliesTo("https://afay-mbp.saml.ldcnh.com");
			rst.setRequestType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");
			rst.setTokenType("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0");

			STSClient idpWamClient = new STSClient(stsIdpClientConfig);

			UsernameToken usernameToken = new UsernameToken();
			usernameToken.setUsername("joe");
			usernameToken.setPassword("2Federate");

			//Retrieves the STS response with a username RST
			STSResponse stsResponse = idpWamClient.makeRequest(rst, usernameToken.getRoot(), null, null);
			samlStsToken = stsResponse.getRstr().getToken();

			//Print the token. Only for debug purposes...
			String formattedRequest2 = utils.prettyPrint(samlStsToken);
			System.out.println(formattedRequest2);

			//Other tokens might be encoded
			//Get the Base64 value
			//String binTokenValue = samlStsToken.getChildNodes().item(0).getNodeValue();
			//System.out.println(binTokenValue);
			//samlToken = binTokenValue;

			//Decode the SAML2 assertion. Only for debug purposes...
			//samlDecoded = new String(Base64.decodeBase64(binTokenValue.getBytes()));
			//System.out.println(samlDecoded);

		} catch (Exception e){
			e.printStackTrace();
		}
		finally{
			return samlStsToken;
		}
	}

	/*
	 * Uses a SAML2 assertion to retrieve a WAM token
	 */    
	@SuppressWarnings("finally")
	public static String getWamToken(Element samlElement) {

		STSClientConfiguration	stsSpClientConfig = new STSClientConfiguration();     
		stsSpClientConfig.setStsEndpoint("https://localhost:9031/sp/sts.wst");
		stsSpClientConfig.setIgnoreSSLTrustErrors(true);

		Element wamStsToken;
		String wamToken = "";
		StringUtils utils = new StringUtils();

		try {

			//Uses the SAML token to request a WAM token. Currently the WAM token type is not included the TokenType enum.
			RequestSecurityTokenData rst = new RequestSecurityTokenData();
			rst.setAppliesTo("https://afay-mbp.saml.ldcnh.com");
			rst.setRequestType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");
			rst.setTokenType("urn:pingidentity:wam");

			STSClient idpWamClient = new STSClient(stsSpClientConfig);
			//Retrieves the STS response with a SAML RST
			STSResponse stsResponse = idpWamClient.makeRequest(rst, samlElement, null, null);
			wamStsToken = stsResponse.getRstr().getToken();

			//Print the token. Only for debug purposes...
			String formattedRequest2 = utils.prettyPrint(wamStsToken);
			System.out.println(formattedRequest2);

			//Get the Base64 value
			wamToken = wamStsToken.getChildNodes().item(0).getNodeValue();
			//System.out.println(binTokenValue);
			//samlToken = binTokenValue;

			//Decode the SAML2 assertion. Only for debug purposes...
			//String samlDecoded = new String(Base64.decodeBase64(binTokenValue.getBytes()));
			//System.out.println(samlDecoded);

		} catch (Exception e){
			e.printStackTrace();
		}
		finally{
			return wamToken;
		}
	}


	/*
	 * Disables SSL hostname and trust verification. (Testing purposes only).
	 */
	public static void disableSSLVerification(){
		TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {

			@Override
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}
			@Override
			public void checkClientTrusted(X509Certificate[] certs, String authType) {
			}
			@Override
			public void checkServerTrusted(X509Certificate[] certs, String authType) {
			}
		}
		};

		try{
			// Install the all-trusting trust manager
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		} catch(Exception e){
			e.printStackTrace();
		}

		// Create all-trusting host name verifier
		HostnameVerifier allHostsValid = new HostnameVerifier() {
			@Override
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		};

		HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);          
	}
}
