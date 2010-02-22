package com.jwhois.core;

import java.util.List;
import java.util.Map;

public class JSONParser {

	@SuppressWarnings("unchecked")
	public static String toJSONString(Object obj) {
		StringBuffer sb = new StringBuffer();

		if (obj instanceof Map) {
			sb.append( toJSONValue( obj ) );
			return sb.toString();
		}

		sb.append( "{" );
		sb.append( toJSONValue( obj ) );
		sb.append( "}" );
		return sb.toString();
	}

	@SuppressWarnings("unchecked")
	public static String toJSONValue(Object obj) {
		StringBuffer sb = new StringBuffer();

		if (obj == null) {
			sb.append( "null" );
			return sb.toString();
		}

		if (obj instanceof String) {
			sb.append( "\"" );
			sb.append( toUnicodeString( escape( ( String ) obj ) ) );
			sb.append( "\"" );
		}
		else if (obj instanceof List) {
			sb.append( "[" );
			List list = ( List ) obj;
			boolean first = true;
			for (Object v : list) {
				if (!first)
					sb.append( "," );
				sb.append( toJSONValue( v ) );
				first = false;
			}
			sb.append( "]" );
		}
		else if (obj instanceof Object[]) {
			sb.append( "[" );
			Object[] list = ( Object[] ) obj;
			boolean first = true;
			for (Object v : list) {
				if (!first)
					sb.append( "," );
				sb.append( toJSONValue( v ) );
				first = false;
			}
			sb.append( "]" );
		}
		else if (obj instanceof Map) {
			sb.append( "{" );
			Map map = ( Map ) obj;
			boolean first = true;
			for (Object k : map.keySet()) {
				if (k instanceof String) {
					if (!first)
						sb.append( "," );
					sb.append( toJSONString( ( String ) k, map.get( k ) ) );
					first = false;
				}
			}
			sb.append( "}" );
		}
		else {
			sb.append( obj.toString() );
		}
		return sb.toString();
	}

	public static String toJSONString(String key, Object value) {
		StringBuffer sb = new StringBuffer();
		sb.append( "\"" );
		sb.append( escape( key ) );
		sb.append( "\":" );
		sb.append( toJSONValue( value ) );
		return sb.toString();
	}

	public static String escape(String s) {
		if (s == null)
			return null;
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < s.length(); i++) {
			char ch = s.charAt( i );
			switch (ch) {
			case '"':
				sb.append( "\\\"" );
				break;
			case '\\':
				sb.append( "\\\\" );
				break;
			case '\b':
				sb.append( "\\b" );
				break;
			case '\f':
				sb.append( "\\f" );
				break;
			case '\n':
				sb.append( "\\n" );
				break;
			case '\r':
				sb.append( "\\r" );
				break;
			case '\t':
				sb.append( "\\t" );
				break;
			case '/':
				sb.append( "\\/" );
				break;
			case '\u0085': // Next Line
				sb.append( "\\u0085" );
				break;
			case '\u2028': // Line Separator
				sb.append( "\\u2028" );
				break;
			case '\u2029': // Paragraph Separator
				sb.append( "\\u2029" );
				break;
			default:
				if (ch >= '\u0000' && ch <= '\u001F') {
					String ss = Integer.toHexString( ch );
					sb.append( "\\u" );
					for (int k = 0; k < 4 - ss.length(); k++) {
						sb.append( '0' );
					}
					sb.append( ss.toUpperCase() );
				}
				else {
					sb.append( ch );
				}
			}
		}//for
		return sb.toString();
	}

	public static String toUnicodeString(String s) {
		StringBuilder sb = new StringBuilder();
		if (null != s && !"".equals( s )) {
			char[] c = s.toCharArray();
			for (int i = 0; i < c.length; i++) {
				if (c[i] > '\u0370') {
					String hex = Integer.toHexString( ( int ) c[i] );
					hex = "\\u" + (hex.length() < 4 ? "0" : "") + hex;
					sb.append( hex );
				}
				else {
					sb.append( c[i] );
				}
			}

		}
		return sb.toString();
	}
}
