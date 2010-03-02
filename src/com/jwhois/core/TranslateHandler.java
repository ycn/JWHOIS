package com.jwhois.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class TranslateHandler extends DefaultHandler {

	private static final String					ROOT	= "JWHOIS";
	private static final String					ITEM	= "Translates";
	private static final String					SUBITEM	= "Item";
	private static final String					KEY		= "Key";
	private static final String					VALUE	= "Translate";
	private static final List<String>			LISTNAME;

	private Map<String, Map<String, Object>>	map;
	private Map<String, Object>					submap;
	private Map<String, String>					contact;
	private String								key;
	private String								value;
	private StringBuilder						builder;

	static {
		LISTNAME = new ArrayList<String>();
		LISTNAME.add( "Contacts" );
		LISTNAME.add( "ContactInfo" );
		LISTNAME.add( "List" );
	}

	public Map<String, Map<String, Object>> getMap() {
		return map;
	}

	@Override
	public void characters(char[] ch, int start, int length) throws SAXException {
		if (map == null) {
			return;
		}
		if (builder != null) {
			builder.append( ch, start, length );
		}
	}

	@Override
	public void startElement(String uri, String localName, String qName, Attributes attributes) throws SAXException {
		String test = localName;
		if (null == test || "".equals( test )) {
			test = qName;
		}
		if (null == test) {
			test = "";
		}

		if (test.equals( ROOT )) {
			map = new HashMap<String, Map<String, Object>>();
		}
		if (map == null) {
			return;
		}
		if (test.equals( ITEM )) {
			submap = new HashMap<String, Object>();

			for (int i = 0; i < attributes.getLength(); i++) {
				String k = attributes.getLocalName( i ).toLowerCase();
				if (null == k || "".equals( k )) {
					k = attributes.getQName( i ).toLowerCase();
				}
				String v = attributes.getValue( i ).toLowerCase();
				if (k.equals( "id" )) {
					map.put( v, submap );
				}
				else {
					submap.put( k, v );
				}
			}

		}
		else if (LISTNAME.contains( test ) && submap != null) {
			contact = new HashMap<String, String>();
			submap.put( test.toLowerCase(), contact );
		}
		else if (test.equals( SUBITEM ) && contact != null) {
			key = "";
			value = "";
		}
		else if (test.equals( KEY )) {
			builder = new StringBuilder();
		}
		else if (test.equals( VALUE )) {
			builder = new StringBuilder();
		}
	}

	@Override
	public void endElement(String uri, String localName, String qName) throws SAXException {
		String test = localName;
		if (null == test || "".equals( test )) {
			test = qName;
		}
		if (null == test) {
			test = "";
		}

		if (test.equals( ROOT )) {
			submap = null;
			contact = null;
			key = "";
			value = "";
			builder = null;
		}
		if (map == null) {
			return;
		}
		if (test.equals( SUBITEM ) && contact != null) {
			if (!Utility.isEmpty( key ) && !Utility.isEmpty( value ))
				contact.put( key, value );
		}
		else if (test.equals( KEY ) && builder != null) {
			key = builder.toString().toLowerCase().trim();
		}
		else if (test.equals( VALUE ) && builder != null) {
			value = builder.toString().toLowerCase().trim();
		}
	}

}
