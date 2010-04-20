package com.jwhois.core;

import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class ServerHandler extends DefaultHandler {

	private static final String					ROOT	= "JWHOIS";
	private static final String					ITEM	= "SERVER";
	private static final String					KEY		= "KEY";
	private static final String					VALUE	= "URL";
	private static final List<String>			LISTNAME;

	private Map<String, Map<String, String>>	map;
	private Map<String, String>					submap;
	private String								key;
	private String								value;
	private StringBuilder						builder;

	static {
		LISTNAME = new ArrayList<String>();
		LISTNAME.add( "SpecialList" );
		LISTNAME.add( "NonICANNList" );
		LISTNAME.add( "RegistrarList" );
		LISTNAME.add( "RedirectList" );
		LISTNAME.add( "CommonServer" );
	}

	public Map<String, Map<String, String>> getMap() {
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
			map = new Hashtable<String, Map<String, String>>();
		}
		if (map == null) {
			return;
		}
		if (LISTNAME.contains( test )) {
			submap = new Hashtable<String, String>();
			map.put( test, submap );
		}
		else if (test.equals( ITEM ) && submap != null) {
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
			key = "";
			value = "";
			builder = null;
		}
		if (map == null) {
			return;
		}
		if (test.equals( ITEM ) && submap != null) {
			if (!Utility.isEmpty( key ) && !Utility.isEmpty( value ))
				submap.put( key, value );
		}
		else if (test.equals( KEY ) && builder != null) {
			key = builder.toString().toLowerCase().trim();
		}
		else if (test.equals( VALUE ) && builder != null) {
			value = builder.toString().trim();
		}
	}

}
