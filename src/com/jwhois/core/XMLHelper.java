package com.jwhois.core;

import java.util.Map;

import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

public final class XMLHelper {
	private static Map<String, Map<String, String>>	servers		= null;
	private static Map<String, Map<String, Object>>	translates	= null;

	public static void preloadXML() {
		buildServers();
		buildTranslates();
	}

	public static boolean isLoad() {
		return (servers != null && translates != null && !servers.isEmpty() && !translates.isEmpty());
	}

	public static void clean() {
		servers = null;
		translates = null;
	}

	private static void buildServers() {
		if (servers != null)
			return;

		SAXParserFactory factory = SAXParserFactory.newInstance();
		try {
			SAXParser parser = factory.newSAXParser();
			ServerHandler handler = new ServerHandler();
			parser.parse( Utility.getServersDB(), handler );
			servers = handler.getMap();
		}
		catch (Exception e) {
			Utility.logWarn( "XMLHelper::buildServers:", e );
		}
	}

	private static void buildTranslates() {
		if (translates != null)
			return;

		SAXParserFactory factory = SAXParserFactory.newInstance();
		try {
			SAXParser parser = factory.newSAXParser();
			TranslateHandler handler = new TranslateHandler();
			parser.parse( Utility.getTranslatesDB(), handler );
			translates = handler.getMap();
		}
		catch (Exception e) {
			Utility.logWarn( "XMLHelper::buildTranslates:", e );
		}

	}

	static String getSpecialServer(String tld, boolean nonIcann) {
		String ret = "";
		if (nonIcann) {
			ret = getServerValue( "NonICANNList", tld );
		}
		if ("".equals( ret )) {
			ret = getServerValue( "SpecialList", tld );
		}
		return ret;
	}

	static String getRegistrarServer(String name) {
		return indexServerValue( "RegistrarList", name );
	}

	static String getRedirectServer(String name) {
		return getServerValue( "RedirectList", name );
	}

	static String getCommonServer() {
		return pickUpSingleServer( "CommonServer" );
	}

	// -- getter utils
	static String pickUpSingleServer(String listname) {
		String ret = "";
		if (null == servers) {
			buildServers();
		}
		if (null != servers) {
			Map<String, String> map = servers.get( listname );
			if (!Utility.isEmpty( map ) && !map.isEmpty()) {
				for (String key : map.keySet()) {
					ret = map.get( key );
					break;
				}
			}
		}
		return ret;
	}

	static String getServerValue(String listname, String key) {
		String ret = "";
		if (null == servers) {
			buildServers();
		}
		if (null != servers) {
			Map<String, String> map = servers.get( listname );
			if (!Utility.isEmpty( map ) && map.containsKey( key.toLowerCase() )) {
				ret = map.get( key.toLowerCase() );
			}
		}
		return ret;
	}

	static String indexServerValue(String listname, String key) {
		String ret = "";
		if (null == servers) {
			buildServers();
		}
		if (null != servers) {
			Map<String, String> map = servers.get( listname );
			if (!Utility.isEmpty( map )) {
				for (String k : map.keySet()) {
					if (key.toLowerCase().indexOf( k ) > -1) {
						ret = map.get( k );
						break;
					}
				}
			}
		}
		return ret;
	}

	static String getTranslateAttr(String attrname, String key) {
		String ret = "";
		if (null == translates) {
			buildTranslates();
		}
		if (null != translates) {
			attrname = attrname.toLowerCase();
			key = key.toLowerCase();
			Map<String, Object> map = translates.get( key );
			if (!Utility.isEmpty( map ) && map.containsKey( attrname )) {
				ret = map.get( attrname ).toString();
			}
		}
		return ret;
	}

	@SuppressWarnings("unchecked")
	static Map<String, String> getTranslateMap(String mapname, String key) {
		Map<String, String> ret = null;
		if (null == translates) {
			buildTranslates();
		}
		if (null != translates) {
			mapname = mapname.toLowerCase();
			key = key.toLowerCase();
			Map<String, Object> map = translates.get( key );
			if (!Utility.isEmpty( map ) && map.containsKey( mapname )) {
				ret = ( Map<String, String> ) map.get( mapname );
			}
		}
		return ret;
	}

}
