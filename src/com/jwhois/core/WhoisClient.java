package com.jwhois.core;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class WhoisClient {
	private static final String	DEFAULT_HOST	= "whois.internic.net";
	private static final String	DEFAULT_IP_HOST	= "whois.arin.net";
	private static final int	DEFAULT_PORT	= 43;
	private static final int	DEFAULT_TIMEOUT	= 15 * 1000;

	protected String			url;
	protected String			ptlType;
	protected String			hostname;
	protected int				port;
	protected String			queryStr;

	private Pattern				pnStart;
	private Pattern				pnEnd;
	private Pattern				pnCatch;

	private LineFilter			filter;
	private String				proxy;

	// Constructor
	public WhoisClient() {
		init();
	}

	private void init() {
		ptlType = "whois";
		port = DEFAULT_PORT;
		url = "";
		hostname = "";
		queryStr = "";
		pnStart = null;
		pnEnd = null;
		pnCatch = null;
	}

	/**
	 * look up WHOIS from domain
	 * 
	 * @param domain
	 * @param tld
	 * @return Line list of WHOIS Raw Data
	 */
	public List<String> domLookup(String domain, String tld) {
		if (Utility.isEmpty( queryStr )) {
			queryStr = "{domain}";
		}
		queryStr = queryStr.replace( "{domain}", domain );
		queryStr = queryStr.replace( "{tld}", tld );
		if (!Utility.isEmpty( url )) {
			url = url.replace( "{domain}", domain );
			url = url.replace( "{tld}", tld );
		}
		if (Utility.isEmpty( hostname )) {
			hostname = DEFAULT_HOST;
		}
		return doQuery();
	}

	/**
	 * look up WHOIS from ip
	 * 
	 * @param ip
	 * @return Line list of WHOIS Raw Data
	 */
	public List<String> ipLookup(String ip) {
		if (Utility.isEmpty( queryStr )) {
			queryStr = "{ip}";
		}
		queryStr = queryStr.replace( "{ip}", ip );
		if (!Utility.isEmpty( url )) {
			url = url.replace( "{ip}", ip );
		}
		if (Utility.isEmpty( hostname )) {
			hostname = DEFAULT_IP_HOST;
		}
		return doQuery();
	}

	private List<String> doQuery() {
		List<String> list = new ArrayList<String>();
		if (("http".equals( ptlType ) || "https".equals( ptlType )) && !Utility.isEmpty( url )) {
			httpQuery( list );
		}
		else if ("whois".equals( ptlType ) && !Utility.isEmpty( hostname ) && !Utility.isEmpty( queryStr )) {
			socketQuery( list );
		}
		// Reset the args
		init();
		return list;
	}

	private void httpQuery(List<String> list) {
		URLConnection conn = null;
		URL url = null;

		if (port == 443) {
			trustAllHosts();
		}

		try {
			url = new URL( this.url );
			conn = url.openConnection();

			List<String> cleanList = Utility.cleanHtml( conn.getInputStream() );

			boolean hasLineStart = (null == pnStart) ? false : true;
			boolean hasLineEnd = (null == pnEnd) ? false : true;
			boolean canRead = hasLineStart ? false : true;
			boolean hasLineCatch = (null == pnCatch) ? false : true;
			if (hasLineCatch) {
				for (String line : cleanList) {
					// Matches
					Matcher m = pnCatch.matcher( line );
					if (m.find() && (m.groupCount() > 0)) {
						String[] slist = m.group( 1 ).split( "<[b|B][r|R]\\s*/?>" );
						for (String l : slist) {
							if (skipLineHTML( l ))
								continue;
							if (!canRead && hasLineStart && pnStart.matcher( l ).find())
								canRead = true;
							if (canRead && hasLineEnd && pnEnd.matcher( l ).find())
								break;
							if (canRead)
								list.add( readingLineHTML( l ) );
						}
						break;
					}
				}
			}
			else {
				for (String line : cleanList) {
					if (skipLineHTML( line ))
						continue;
					if (!canRead && hasLineStart && pnStart.matcher( line ).find())
						canRead = true;
					if (canRead && hasLineEnd && pnEnd.matcher( line ).find())
						break;
					if (canRead)
						list.add( readingLineHTML( line ) );
				}
			}
		}
		catch (MalformedURLException e) {
			Utility.logWarn( "WhoisClient::httpQuery MalformedURLException: <url:" + this.url + ">", e );
		}
		catch (IOException e) {
			Utility.logWarn( "WhoisClient::httpQuery IOException: <url:" + this.url + ">", e );
		}
	}

	private void socketQuery(List<String> list) {
		PrintWriter pw = null;
		BufferedReader br = null;
		Socket sock = null;

		try {
			InetAddress addr = InetAddress.getByName( hostname );
			InetSocketAddress sAddr = new InetSocketAddress( addr, port );
			sock = this.getConnectSocket( sAddr );
			if (null == sock)
				return;
			sock.setSoTimeout( DEFAULT_TIMEOUT );
			pw = new PrintWriter( sock.getOutputStream() );
			pw.print( queryStr + "\r\n" );
			pw.flush();

			br = new BufferedReader( new InputStreamReader( sock.getInputStream(), "UTF-8" ) );
			String line = null;
			boolean hasLineStart = (null == pnStart) ? false : true;
			boolean hasLineEnd = (null == pnEnd) ? false : true;
			boolean canRead = hasLineStart ? false : true;
			while ((line = br.readLine()) != null) {
				if (skipLine( line ))
					continue;
				if (!canRead && hasLineStart && pnStart.matcher( line ).find())
					canRead = true;
				if (canRead && hasLineEnd && pnEnd.matcher( line ).find())
					break;
				if (canRead)
					list.add( readingLine( line ) );
			}
		}
		catch (UnknownHostException e) {
			Utility.logWarn( "WhoisClient::socketQuery UnknownHostException: <host:" + this.hostname + "><query:"
					+ this.queryStr + ">", e );
		}
		catch (SocketException e) {
			Utility.logWarn( "WhoisClient::socketQuery SocketException: <host:" + this.hostname + "><query:"
					+ this.queryStr + ">", e );
		}
		catch (IOException e) {
			Utility.logWarn( "WhoisClient::socketQuery IOException: <host:" + this.hostname + "><query:"
					+ this.queryStr + ">", e );
		}
		finally {
			try {
				if (null != pw)
					pw.close();
				if (null != br)
					br.close();
				if (null != sock)
					sock.close();
			}
			catch (IOException e) {
				// do nothing
			}
		}

	}

	/**
	 * set the internal arguments from server address
	 * 
	 * @param server
	 */
	public void setServer(String server) {
		String addr = server;

		// keep in url.
		url = addr;

		int posPtl = addr.indexOf( "://" );
		if (posPtl > -1) {
			String ptlStr = addr.substring( 0, posPtl ).toLowerCase();
			if ("http".equals( ptlStr )) {
				ptlType = "http";
				port = 80;
			}
			else if ("https".equals( ptlStr )) {
				ptlType = "http";
				port = 443;
			}
		}

		// Get rid of "xxxx://"
		posPtl = posPtl <= -1 ? 0 : posPtl + 3;
		addr = addr.substring( posPtl );

		int posPort = addr.indexOf( ':' );
		int posSlash = addr.indexOf( '/' );
		int posArgs = addr.indexOf( '?' );
		int posAs = posSlash;
		if (posSlash != -1 && (posSlash < posArgs || posArgs == -1)) {
			queryStr = addr.substring( posSlash );
		}
		else {
			queryStr = posArgs <= -1 ? null : addr.substring( posArgs + 1 );
			posAs = posArgs <= -1 ? addr.length() : posArgs;
		}

		// Get the port
		if (posPort != -1) {
			port = Integer.parseInt( addr.substring( posPort + 1, posAs ) );
		}

		// Get the hostname
		posPort = posPort <= -1 ? posAs : posPort;
		hostname = addr.substring( 0, posPort ).toLowerCase();
	}

	// Interfaces
	public void setLineStartFilter(String str) {
		if (!Utility.isEmpty( str )) {
			try {
				pnStart = Pattern.compile( str, Pattern.CASE_INSENSITIVE );
			}
			catch (PatternSyntaxException e) {
				Utility.logWarn( "WhoisClient::setLineStartFilter PatternSyntaxException: <host:" + this.hostname
						+ "><pattern:" + str + ">", e );
			}
		}
	}

	public void setLineEndFilter(String str) {
		if (!Utility.isEmpty( str )) {
			try {
				pnEnd = Pattern.compile( str, Pattern.CASE_INSENSITIVE );
			}
			catch (PatternSyntaxException e) {
				Utility.logWarn( "WhoisClient::setLineEndFilter PatternSyntaxException: <host:" + this.hostname
						+ "><pattern:" + str + ">", e );
			}
		}
	}

	public void setLineCatchFilter(String str) {
		if (!Utility.isEmpty( str )) {
			try {
				pnCatch = Pattern.compile( str, Pattern.CASE_INSENSITIVE );
			}
			catch (PatternSyntaxException e) {
				Utility.logWarn( "WhoisClient::setLineCatchFilter PatternSyntaxException: <host:" + this.hostname
						+ "><pattern:" + str + ">", e );
			}
		}
	}

	public void setLineFilter(LineFilter filter) {
		this.filter = filter;
	}

	private String readingLine(String line) {
		if (null != filter)
			return filter.filterLine( line );
		return line;
	}

	private String readingLineHTML(String line) {
		if (null != filter)
			return filter.filterHtmlLine( line );
		return line;
	}

	private boolean skipLine(String line) {
		if (null != filter)
			return filter.skipLine( line );
		return false;
	}

	private boolean skipLineHTML(String line) {
		if (null != filter)
			return filter.skipHtmlLine( line );
		return false;
	}

	private Socket getConnectSocket(SocketAddress addr) {
		if (null == addr)
			return null;
		Socket sock = null;
		int retryTimes = 0;
		while (retryTimes < 6) {
			try {
				proxy = Utility.getProxy();
				if (null != proxy) {
					String[] ss = proxy.split( ":" );
					if (ss.length > 1) {
						Proxy p = new Proxy( Proxy.Type.SOCKS, new InetSocketAddress( ss[0], Integer.parseInt( ss[1] ) ) );
						sock = new Socket( p );
						sock.setSoTimeout( DEFAULT_TIMEOUT );
					}
				}
				else {
					sock = new Socket();
				}
				sock.connect( addr, 1000 );
			}
			catch (Exception e) {
				// Nothing to do.
			}
			finally {
				if (sock.isConnected())
					return sock;
				retryTimes++;
			}
		}
		return null;
	}
	
	public String getProxy() {
		return proxy;
	}

	private void trustAllHosts() {
		// Create a trust manager that does not validate certificate chains
		TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return new java.security.cert.X509Certificate[] {};
			}

			public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			}

			public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
			}
		} };

		// Install the all-trusting trust manager
		try {
			SSLContext sc = SSLContext.getInstance( "TLS" );
			sc.init( null, trustAllCerts, new java.security.SecureRandom() );
			HttpsURLConnection.setDefaultSSLSocketFactory( sc.getSocketFactory() );
		}
		catch (Exception e) {
		}
	}

}
