package com.jwhois.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

import com.jwhois.core.Logger.LEVEL;

public class Utility {
	public static final String	REGEXP_HTMLUTIL		= "<[^>]+?>";
	public static final String	REGEXP_BLANK		= "\\s*";
	public static final String	REGEXP_SLD_IDN		= "(xn--)?[a-z0-9](([a-z0-9-]+)?[a-z0-9])?";
	public static final String	REGEXP_TLD			= "(\\.[a-z]{2,10})(\\.[a-z]{2,3})?";
	public static final String	REGEXP_DOMAIN		= REGEXP_SLD_IDN + REGEXP_TLD;
	public static final String	REGEXP_IP			= "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)";

	private static Logger		logger;
	private static IProxy		proxyFactory;

	// Default Global Settings
	private static final String	WHOIS_SERVERS_DB	= "WhoisServers.xml";
	private static final String	WHOIS_TRANSLATES_DB	= "WhoisTranslates.xml";

	static final boolean		DEBUG				= false;

	static InputStream getServersDB() {
		return com.jwhois.core.Utility.class.getResourceAsStream( WHOIS_SERVERS_DB );
	}

	static InputStream getTranslatesDB() {
		return com.jwhois.core.Utility.class.getResourceAsStream( WHOIS_TRANSLATES_DB );
	}

	/**
	 * check if a string is empty
	 * 
	 * @param str
	 * @return [flag]
	 */
	public static boolean isEmpty(String str) {
		return ((null == str) || str.matches( REGEXP_BLANK ));
	}

	/**
	 * check if a array is empty
	 * 
	 * @param str
	 * @return [flag]
	 */
	public static boolean isEmpty(Object[] arr) {
		return ((null == arr) || arr.length == 0);
	}

	/**
	 * check if a List<?> is empty
	 * 
	 * @param list
	 * @return [flag]
	 */
	public static boolean isEmpty(List<?> list) {
		return ((null == list) || list.isEmpty());
	}

	/**
	 * check if a Map<String,?> is empty
	 * 
	 * @param map
	 * @return [flag]
	 */
	public static boolean isEmpty(Map<String, ?> map) {
		return ((null == map) || map.isEmpty());
	}

	/**
	 * check if a domain name(after IDN) is valid
	 * 
	 * @param domain
	 * @return [flag]
	 */
	public static boolean isValidDom(String domain) {
		return ((null != domain) && domain.matches( REGEXP_DOMAIN ));
	}

	/**
	 * check if an IP is a valid IP
	 * 
	 * @param ip
	 * @return [flag]
	 */
	public static boolean isValidIP(String ip) {
		return ((null != ip) && ip.matches( REGEXP_IP ));
	}

	/**
	 * Build array of all possible tld's for that domain
	 * 
	 * @param domain
	 * @return ArrayList of all possible tlds.
	 */
	public static List<String> buildTLDs(String domain) {
		ArrayList<String> tlds = new ArrayList<String>();
		String tld = domain;
		int pos = -1;
		while ((pos = tld.indexOf( '.' )) > -1) {
			tld = tld.substring( pos + 1 );
			tlds.add( tld );
		}
		return tlds;
	}

	/**
	 * get the IP address of the given domain.
	 * 
	 * @param domain
	 * @return the IP address. return "" if there is a bad domain.
	 */
	public static String getAddressbyName(String domain) {
		String host = "";
		try {
			InetAddress addr = InetAddress.getByName( domain );
			host = addr.getHostAddress();
		}
		catch (UnknownHostException e) {
			// do nothing
		}
		return host;
	}

	/**
	 * get the host name of a url string
	 * 
	 * @param url
	 * @return the host name. return "" if there is a bad url.
	 */
	public static String getHostName(String url) {
		String host = "";
		if (url.indexOf( "://" ) == -1)
			return url;
		URL u;
		try {
			u = new URL( url );
			host = u.getHost();
		}
		catch (MalformedURLException e) {
			// do nothing
		}
		return host;
	}

	/**
	 * Checks the URL, see if it is available.
	 * 
	 * @param url
	 * @return [flag]
	 */
	public static boolean checkURL(String url) {
		url = url.toLowerCase();
		URL u = null;
		int code = -1;
		try {
			u = new URL( url );

			if (url.startsWith( "http://" )) {
				HttpURLConnection conn = ( HttpURLConnection ) u.openConnection();
				code = conn.getResponseCode();
			}
			else if (url.startsWith( "https://" )) {
				HttpsURLConnection conn = ( HttpsURLConnection ) u.openConnection();
				conn.setHostnameVerifier( new HostnameVerifier() {
					public boolean verify(String hostname, SSLSession session) {
						return true;
					}
				} );
				code = conn.getResponseCode();
			}
		}
		catch (IOException e) {
			// do nothing
		}
		return (code == 200) ? true : false;
	}

	/**
	 * set the interface for outer Logger
	 * 
	 * @param l
	 */
	public static void setLogger(Logger l) {
		logger = l;
	}

	public static void setProxyFactory(IProxy p) {
		proxyFactory = p;
	}

	public static boolean hasProxyFactory() {
		if (proxyFactory != null)
			return true;
		return false;
	}
	
	public static String getProxy() {
		if (proxyFactory == null)
			return null;
		return proxyFactory.getProxy();
	}

	public static void logErr(String title, Exception e) {
		if (null != logger)
			logger.doLog( LEVEL.ERROR, title + " | ", e );
		else
			System.out.println( "[ERROR] - jWhois - " + title + e.getMessage() );
	}

	public static void logWarn(String title, Exception e) {
		if (null != logger)
			logger.doLog( LEVEL.WARN, title, e );
		else
			System.out.println( "[WARN] - jWhois - " + title + e.getMessage() );
	}

	public static void logInfo(String title) {
		if (null != logger)
			logger.doLog( LEVEL.INFO, title, null );
		else
			System.out.println( "[INFO] - jWhois - " + title );
	}

	public static void logDebug(String title, Exception e) {
		if (DEBUG) {
			System.out.print( "#### " + "[DEBUG] - jWhois - " + title );
			if (null != e)
				e.printStackTrace();
			System.out.println( " (END) ####" );
		}
	}

	private static String skipLine(String line) {
		String l = "";
		if (line.indexOf( "<" ) >= 0 && line.indexOf( ">" ) == -1)
			return l;
		if (line.indexOf( ">" ) >= 0 && line.indexOf( "<" ) == -1)
			return l;
		line = line.replaceAll( "&lt;", "<" );
		line = line.replaceAll( "&gt;", ">" );
		line = line.replaceAll( "&nbsp;", " " );
		line = line.replaceAll( "&amp;", "&" );
		return line;
	}

	/**
	 * makes the given html stream clean
	 * 
	 * @param in
	 * @return clean list of lines
	 */
	public static List<String> cleanHtml(InputStream in) {
		List<String> list = new ArrayList<String>();

		try {
			BufferedReader br = new BufferedReader( new InputStreamReader( in, "UTF-8" ) );
			String line = null;
			boolean skip = false;
			while ((line = br.readLine()) != null) {
				line = line.replaceAll( REGEXP_HTMLUTIL, "" );
				if (Utility.isEmpty( line ))
					continue;
				if (skip && line.indexOf( "-->" ) >= 0) {
					skip = false;
					continue;
				}
				if (!skip && line.indexOf( "<!--" ) >= 0) {
					skip = true;
				}
				if (skip) {
					continue;
				}
				line = skipLine( line );
				if (!Utility.isEmpty( line ))
					list.add( line );
			}

			br.close();
		}
		catch (Exception e) {
			// do nothing
		}

		return list;
	}

}
