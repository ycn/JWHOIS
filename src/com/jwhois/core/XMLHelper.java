package com.jwhois.core;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public final class XMLHelper {
	private static Map<String, Map<String, String>>	servers;
	private static Map<String, Map<String, Object>>	translates;

	static {
		buildServers();
		buildTranslates();
	}

	public static Element getFirstElement(String tagName, Element target) {
		Element elm = null;
		NodeList list = target.getElementsByTagName( tagName );
		if (null != list && list.getLength() > 0) {
			elm = ( Element ) list.item( 0 );
		}
		return elm;
	}

	public static String getFirstElementText(String tagName, Element target) {
		String text = "";
		NodeList list = target.getElementsByTagName( tagName );
		if (null != list && list.getLength() > 0) {
			text = list.item( 0 ).getTextContent().trim();
		}
		return text;
	}

	public static List<Element> getAllElements(Element target) {
		List<Element> ret = new ArrayList<Element>();

		NodeList list = target.getChildNodes();
		for (int i = 0; i < list.getLength(); i++) {
			Node node = list.item( i );
			if (node.getNodeType() == 1) {
				ret.add( ( Element ) node );
			}
		}

		return ret.isEmpty() ? null : ret;
	}

	public static void reloadXML() {
		buildServers();
		buildTranslates();
	}

	private static void buildServers() {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = null;
		Document doc = null;
		try {
			builder = factory.newDocumentBuilder();
			doc = builder.parse( Utility.getServersDB() );
		}
		catch (IOException e) {
			Utility.logWarn( "XMLHelper::buildServers IOException:", e );
		}
		catch (SAXException e) {
			Utility.logWarn( "XMLHelper::buildServers SAXException:", e );
		}
		catch (ParserConfigurationException e) {
			Utility.logWarn( "XMLHelper::buildServers ParserConfigurationException:", e );
		}
		if (null != doc) {
			servers = new HashMap<String, Map<String, String>>();
			Element root = doc.getDocumentElement();

			if ("JWHOIS".equals( root.getTagName() )) {
				List<Element> list = getAllElements( root );
				if (null != list && list.size() > 0) {
					for (Element elm : list) {
						Map<String, String> map = new HashMap<String, String>();
						servers.put( elm.getTagName().toLowerCase(), map );
						buildServerMap( elm, map );
					}
				}
			}
		}
	}

	private static void buildServerMap(Element elm, Map<String, String> map) {
		NodeList list = elm.getElementsByTagName( "SERVER" );
		if (null != list) {
			for (int i = 0; i < list.getLength(); i++) {
				Element e = ( Element ) list.item( i );
				String key = getFirstElementText( "KEY", e ).toLowerCase();
				String val = getFirstElementText( "URL", e );
				if (!Utility.isEmpty( key ) && !Utility.isEmpty( val ))
					map.put( key, val );
			}
		}
	}

	private static void buildTranslates() {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		DocumentBuilder builder = null;
		Document doc = null;
		try {
			builder = factory.newDocumentBuilder();
			doc = builder.parse( Utility.getTranslatesDB() );
		}
		catch (IOException e) {
			Utility.logWarn( "XMLHelper::buildTranslates IOException:", e );
		}
		catch (SAXException e) {
			Utility.logWarn( "XMLHelper::buildTranslates SAXException:", e );
		}
		catch (ParserConfigurationException e) {
			Utility.logWarn( "XMLHelper::buildTranslates ParserConfigurationException:", e );
		}
		if (null != doc) {
			translates = new HashMap<String, Map<String, Object>>();
			Element root = doc.getDocumentElement();

			if ("JWHOIS".equals( root.getTagName() )) {
				NodeList list = root.getElementsByTagName( "Translates" );
				if (null != list && list.getLength() > 0) {
					for (int i = 0; i < list.getLength(); i++) {
						Element elm = ( Element ) list.item( i );
						String key = elm.getAttribute( "id" );
						if (!Utility.isEmpty( key )) {
							key = key.toLowerCase();
							Map<String, Object> map = new HashMap<String, Object>();
							translates.put( key, map );
							buildTranslateMap( elm, map );
						}
					}
				}
			}
		}
	}

	private static void buildTranslateMap(Element elm, Map<String, Object> map) {
		NamedNodeMap attrs = elm.getAttributes();
		List<Element> lists = getAllElements( elm );

		if (null != attrs && attrs.getLength() > 0 && null != lists) {
			// insert attributes
			for (int i = 0; i < attrs.getLength(); i++) {
				Node attr = attrs.item( i );
				map.put( attr.getNodeName().toLowerCase(), attr.getNodeValue().toLowerCase() );
			}

			// insert child lists
			for (Element list : lists) {
				Map<String, String> contact = new HashMap<String, String>();
				map.put( list.getTagName().toLowerCase(), contact );
				buildContactMap( list, contact );
			}
		}
	}

	private static void buildContactMap(Element elm, Map<String, String> map) {
		NodeList list = elm.getElementsByTagName( "Item" );
		if (null != list) {
			for (int i = 0; i < list.getLength(); i++) {
				Element e = ( Element ) list.item( i );
				String key = getFirstElementText( "Key", e ).toLowerCase();
				String val = getFirstElementText( "Translate", e ).toLowerCase();
				if (!Utility.isEmpty( key ) && !Utility.isEmpty( val ))
					map.put( key, val );
			}
		}
	}

	static String getSpecialServer(String tld, boolean nonIcann) {
		String ret = "";
		if (nonIcann) {
			ret = getServerValue( "NonICANNList", tld );
		}
		if (ret.isEmpty()) {
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
		if (null != servers) {
			Map<String, String> map = servers.get( listname.toLowerCase() );
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
		if (null != servers) {
			Map<String, String> map = servers.get( listname.toLowerCase() );
			if (!Utility.isEmpty( map ) && map.containsKey( key.toLowerCase() )) {
				ret = map.get( key.toLowerCase() );
			}
		}
		return ret;
	}

	static String indexServerValue(String listname, String key) {
		String ret = "";
		if (null != servers) {
			Map<String, String> map = servers.get( listname.toLowerCase() );
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
