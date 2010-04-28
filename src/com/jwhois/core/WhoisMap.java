package com.jwhois.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class WhoisMap {

	/*
	 *  == The WHOIS Map ==
	 * 
	 *  + regyinfo
	 *  	- hasrecord
	 *  	- whois
	 *  	- whoisdetail
	 *  	- registrar
	 *  	- referrer
	 *  
	 *  + regrinfo
	 *  	+ domain
	 *  		- name
	 *  		- sponsor
	 *  		- nserver
	 *  		- status
	 *  		- created
	 *  		- changed
	 *  		- expires
	 *  	+ owner
	 *  	+ admin
	 *  	+ bill
	 *  	+ tech
	 *  	+ zone
	 *  	+ abuse
	 *  	+ network
	 *  
	 *  - rawdata
	 */

	// line type B : key = group(1); value = group(3)
	private final static String	REGEX_LINEB	= "^\\s*([\u0000-\u0039\u003B-\u007E]+)\\s*(:|[\\.]{3,}|\\s{5,})\\s*([^\\/][^\\/].*)\\s*$";

	private static Pattern		pnLineB;

	static {
		pnLineB = Pattern.compile( REGEX_LINEB, Pattern.CASE_INSENSITIVE );
	}

	private Map<String, Object>	whoisMap;
	private String				deepSvr;

	public WhoisMap() {
		this.whoisMap = new LinkedHashMap<String, Object>();
	}

	public WhoisMap(Map<String, Object> whoisMap) {
		this.whoisMap = whoisMap;
	}

	@SuppressWarnings("unchecked")
	void parse(String server) {
		if (null == whoisMap || Utility.isEmpty( server )) {
			set( "regyinfo.hasrecord", false );
			return;
		}

		List<String> rawdata = ( List<String> ) get( "rawdata" );
		if (Utility.isEmpty( rawdata )) {
			set( "regyinfo.hasrecord", false );
			return;
		}

		// prepare xml data
		Map<String, String> translates = XMLHelper.getTranslateMap( "List", server );
		Map<String, String> contacts = XMLHelper.getTranslateMap( "Contacts", server );
		Map<String, String> contactInfo = XMLHelper.getTranslateMap( "ContactInfo", server );

		String parser = XMLHelper.getTranslateAttr( "Parser", server );
		if (Utility.isEmpty( parser ))
			parser = "a";

		// Generate the RDMap ( the Raw Data Map )
		Map<String, Object> rdMap = null;

		if ("a".equals( parser )) {
			rdMap = parseA( rawdata, contacts );
		}
		else if ("b".equals( parser )) {
			String blockHead = XMLHelper.getTranslateAttr( "BlockHead", server );
			String contactHandle = XMLHelper.getTranslateAttr( "ContactHandle", server );
			String[] blockHeads = Utility.isEmpty( blockHead ) ? null : blockHead.split( "," );
			String[] contactHandles = Utility.isEmpty( contactHandle ) ? null : contactHandle.split( "," );
			rdMap = parseB( rawdata, contacts, blockHeads, contactHandles );
		}
		else if ("c".equals( parser )) {
			rdMap = parseC( rawdata );
		}

		// Keep the hasrecord flag in whoisMap
		set( "regyinfo.hasrecord", !rdMap.isEmpty() );

		if (Utility.isEmpty( rdMap )) {
			return;
		}

		// Translate the RDMap
		for (String key : rdMap.keySet()) {
			Object val = rdMap.get( key );

			if (null == val)
				continue;

			// Parse Contact Info.
			if (!Utility.isEmpty( contacts ) && contacts.containsValue( key )) {
				String[] keys = key.split( "," );

				for (String k : keys) {
					set( k, parseContact( ( List<String> ) val, contactInfo, parser ) );
				}
			}

			// Do Translate.
			if (!Utility.isEmpty( translates ) && translates.containsKey( key )) {
				String translate = translates.get( key );

				if (!Utility.isEmpty( translate )) {
					String[] trans = translate.split( "," );

					for (String t : trans) {
						if (t.startsWith( "k|" )) {
							set( t.substring( 2 ), key + ": " + val );
						}
						else {
							set( t, val, true );
						}
					}
				}
			}
		}

		// Need more deep?
		deepSvr = getString( get( "regyinfo.whois" ) );

		if (Utility.isEmpty( deepSvr )) {
			String tmp = getString( get( "regyinfo.registrar" ) );
			tmp = XMLHelper.getRegistrarServer( tmp );
			if (!Utility.isEmpty( tmp )) {
				tmp = tmp.toLowerCase();
				if ("common".equals( tmp ))
					deepSvr = XMLHelper.getCommonServer();
				else if ("break".equals( tmp ))
					deepSvr = "";
				else
					deepSvr = tmp;
			}
		}

		if (Utility.isEmpty( deepSvr )) {
			deepSvr = getString( get( "regyinfo.whoisdetail" ) );
		}

		if (!Utility.isEmpty( deepSvr )) {
			String redirec = XMLHelper.getRedirectServer( Utility.getHostName( deepSvr ) );
			if (!Utility.isEmpty( redirec )) {
				if ("common".equals( redirec ))
					deepSvr = XMLHelper.getCommonServer();
				else if ("break".equals( redirec ))
					deepSvr = "";
				else
					deepSvr = redirec;
			}
		}
	}

	String deepServer() {
		return deepSvr;
	}

	private Object parseContact(List<String> contactList, Map<String, String> contactInfo, String parser) {
		Object ret = contactList;

		if (Utility.isEmpty( contactList ))
			return ret;

		List<String> list = new ArrayList<String>();
		WhoisMap map = new WhoisMap();

		if ("a".equals( parser )) {
			// The 1st line needs to be parse separately.
			String lineOne = contactList.remove( 0 );
			if (!Utility.isEmpty( lineOne )) {
				Matcher matcher = pnLineB.matcher( lineOne );
				if (matcher.find()) {
					String val = matcher.group( 3 );
					if (!Utility.isEmpty( val ))
						list.add( val );
				}
			}
		}

		// Deal with other lines.
		String cache = null;
		for (String line : contactList) {
			if (!Utility.isEmpty( contactInfo )) {
				Matcher m = pnLineB.matcher( line );
				if (m.find()) {
					cache = null;
					String key = m.group( 1 ).trim().toLowerCase();
					if (contactInfo.containsKey( key )) {
						cache = contactInfo.get( key );
						String[] caches = cache.split( "," );
						for (String s : caches) {
							String mk = s, mv = m.group( 3 ).trim();
							if (s.startsWith( "k|" )) {
								mk = s.substring( 2 );
								mv = key + ": " + mv;
							}
							if (mk.indexOf( '.' ) >= 1) {
								set( mk, mv, true );
							}
							else {
								map.set( mk, mv, true );
							}
						}
						continue;
					}
				}
				else if (null != cache) {
					map.set( cache, line, true );
					continue;
				}
			}
			list.add( line );
		}

		// Create the return Object.
		if (!Utility.isEmpty( map.getMap() )) {
			ret = map;
			if (!Utility.isEmpty( list )) {
				map.set( "info", list, true );
			}
		}
		else if (!Utility.isEmpty( list )) {
			ret = list;
		}
		return ret;
	}

	/*
	 *  == WHOIS RAWDATA TYPE A ==
	 *  
	 *  k:v
	 *  k:v
	 *  ...
	 *  a contact
	 *  	... (contact info)
	 *  	...
	 *  another contact
	 *  	... (contact info)
	 *  	...
	 *  k:v
	 *  ...
	 */
	private Map<String, Object> parseA(List<String> rawdata, Map<String, String> contacts) {
		WhoisMap rdMap = new WhoisMap();

		List<String> cList = null;
		boolean cRead = false;

		for (String line : rawdata) {
			if (!Utility.isEmpty( contacts )) {
				String test = line.trim().toLowerCase();
				// If we find a contact prefix, read to its end and save as line list.
				for (String key : contacts.keySet()) {
					if (test.startsWith( key )) {
						String val = contacts.get( key );

						if ("break".equals( val )) {
							cRead = false;
							break;
						}
						else {
							cList = new ArrayList<String>();
							rdMap.getMap().put( val, cList );
							cRead = true;
							break;
						}
					}
				}
				if (cRead) {
					cList.add( line.trim() );
					continue;
				}
			}

			// We only takes the line matches REGEX_BLINE
			Matcher m = pnLineB.matcher( line );
			if (m.find()) {
				rdMap.set( m.group( 1 ).trim().toLowerCase(), m.group( 3 ).trim(), true );
			}
		}
		return rdMap.getMap();
	}

	private boolean inArray(Object o, Object[] arr) {
		if (o == null || arr == null || arr.length == 0)
			return false;
		for (Object a : arr) {
			if (o.equals( a )) {
				return true;
			}
		}
		return false;
	}

	/*
	 *  == WHOIS RAWDATA TYPE B ==
	 *  
	 *  k:v
	 *  k:v
	 *  contact:handle
	 *  contact:handle
	 *  ...
	 *  [block head]:handle
	 *  	... (contact info)
	 *  	...
	 *  [block head]:handle
	 *  	... (contact info)
	 *  	...
	 *  k:v
	 *  ...
	 */
	private Map<String, Object> parseB(List<String> rawdata, Map<String, String> contacts, String[] blockHeads,
			String[] contactHandles) {
		WhoisMap rdMap = new WhoisMap();

		Map<String, String> cMap = new HashMap<String, String>();
		Map<String, List<String>> hdlMap = new HashMap<String, List<String>>();
		List<String> cList = null;
		boolean cRead = false;

		L1: for (String line : rawdata) {
			Matcher m = pnLineB.matcher( line );
			if (m.find()) {
				String key = m.group( 1 ).trim().toLowerCase();
				String val = m.group( 3 ).trim();
				if (!Utility.isEmpty( blockHeads ) && !Utility.isEmpty( contactHandles ) && inArray( key, blockHeads )) {
					if ("break".equals( contacts.get( key ) )) {
						cRead = false;
						continue;
					}
					else {
						cList = new ArrayList<String>();
						cRead = true;
					}
				}
				if (cRead && (null != cList)) {
					cList.add( line );
					if (inArray( key, contactHandles )) {
						hdlMap.put( val, cList );
					}
					continue;
				}

				// If we find a contact, save it for secondary finding.
				if (!Utility.isEmpty( contacts ) && contacts.containsKey( key )) {
					cMap.put( contacts.get( key ), val );
					continue L1;
				}
				rdMap.set( key, val, true );
			}
		}

		// Rebuild the contacts, if have some.
		if (!Utility.isEmpty( cMap )) {
			for (String contact : cMap.keySet()) {
				String hdl = cMap.get( contact );
				for (String key : hdlMap.keySet()) {
					if (hdl.startsWith( key )) {
						rdMap.getMap().put( contact, hdlMap.get( key ) );
					}
				}
			}
		}
		return rdMap.getMap();
	}

	/*
	 *  == WHOIS RAWDATA TYPE C ==
	 *  
	 *  k ...... v
	 *  k ...... v
	 *  k ...... v
	 *  ...
	 */
	private Map<String, Object> parseC(List<String> rawdata) {
		WhoisMap rdMap = new WhoisMap();
		for (String line : rawdata) {
			Matcher m = pnLineB.matcher( line );
			if (m.find()) {
				String key = m.group( 1 ).trim().toLowerCase();
				String val = m.group( 3 ).trim();
				rdMap.set( key, val, true );
			}
		}
		return rdMap.getMap();
	}

	/**
	 * Sets the map's content indexing by the mapping key. And also, it is safe for giving a null or empty string value
	 * which will do nothing to the current map. This method default not replace the value in map.
	 * 
	 * @param whoisMap
	 *            The given map.
	 * @param key
	 *            The mapping key. (etc. "key1.key2.key3")
	 * @param value
	 *            The value to set.
	 */
	public void set(String key, Object value) {
		set( key, value, false );
	}

	/**
	 * Sets the map's content indexing by the mapping key. And also, it is safe for giving a null or empty string value
	 * which will do nothing to the current map.
	 * 
	 * @param whoisMap
	 *            The given map.
	 * @param key
	 *            The mapping key. (etc. "key1.key2.key3")
	 * @param value
	 *            The value to set.
	 * @param append
	 *            The flag that identify whether to append when setting value.
	 */
	@SuppressWarnings("unchecked")
	public void set(String key, Object value, boolean append) {
		if (null == whoisMap || Utility.isEmpty( key ) || null == value)
			return;

		// we need only the map
		if (value instanceof WhoisMap) {
			value = (( WhoisMap ) value).getMap();
		}

		String[] keys = key.split( "\\b\\.\\b" );
		String sKey = keys[0];
		Object sObj = whoisMap.get( sKey );

		if (keys.length > 1) {
			if (null == sObj) {
				sObj = new LinkedHashMap<String, Object>();
				whoisMap.put( sKey, sObj );
			}

			String leftKey = null;
			int pos = -1;
			if ((pos = key.indexOf( '.' )) > -1)
				leftKey = key.substring( pos + 1 );

			new WhoisMap( ( Map<String, Object> ) sObj ).set( leftKey, value, append );
		}
		else if (null != sObj && append) {
			if (sObj instanceof Map) {
				(( Map<String, Object> ) sObj).put( sKey, value );
			}
			else if (sObj instanceof List) {
				List<String> list = ( List<String> ) sObj;

				if (value instanceof Map) {
					Map<String, String> map = ( Map<String, String> ) value;

					for (String key2 : map.keySet()) {
						addValue( list, key2 + " " + map.get( key2 ) );
					}
				}
				else if (value instanceof List) {
					List<String> nlist = ( List<String> ) value;

					for (String v : nlist) {
						addValue( list, v );
					}
				}
				else {
					addValue( list, value.toString() );
				}
			}
			else {
				List<String> list = new ArrayList<String>();
				whoisMap.put( sKey, list );
				addValue( list, sObj.toString() );
				addValue( list, value.toString() );
			}
		}
		else {
			whoisMap.put( sKey, value );
		}
	}

	/**
	 * Gets the map's content indexing by the mapping key.
	 * 
	 * @param whoisMap
	 *            The given map.
	 * @param key
	 *            The mapping key. (etc. "key1.key2.key3")
	 * @return The object where could be found in the map.
	 */
	@SuppressWarnings("unchecked")
	public Object get(String key) {
		if ((null == whoisMap) || Utility.isEmpty( key ))
			return null;

		String[] keys = key.split( "\\." );
		String sKey = keys[0];
		Object sObj = whoisMap.get( sKey );

		if (keys.length > 1 && null != sObj && sObj instanceof Map) {
			String leftKey = "";
			int pos = key.indexOf( '.' );
			if (pos != -1)
				leftKey = key.substring( pos + 1 );

			return new WhoisMap( ( Map<String, Object> ) sObj ).get( leftKey );
		}

		return sObj;
	}

	/**
	 * Removes the whois map with the map key.
	 * 
	 * @param whoisMap
	 *            The whois map.
	 * @param key
	 *            The map key.
	 * @return The removed object.
	 */
	@SuppressWarnings("unchecked")
	public Object remove(String key) {
		if ((null == whoisMap) || Utility.isEmpty( key ))
			return null;

		String[] keys = key.split( "\\." );
		String sKey = keys[0];
		Object sObj = whoisMap.get( sKey );

		if (null == sObj)
			return null;

		String rightKey = "";
		int pos = key.indexOf( '.' );
		if (pos != -1)
			rightKey = key.substring( pos + 1 );

		if (keys.length > 1 && sObj instanceof Map) {
			return new WhoisMap( ( Map<String, Object> ) sObj ).remove( rightKey );
		}

		if (Utility.isEmpty( rightKey ))
			whoisMap.remove( sKey );

		return sObj;
	}

	public String getJSON() {
		return JSONParser.toJSONString( whoisMap );
	}

	@SuppressWarnings("unchecked")
	private String getString(Object obj) {
		String ret = "";
		if (null != obj) {
			if (obj instanceof List) {
				List<String> list = ( List<String> ) obj;

				if (!Utility.isEmpty( list ))
					ret = list.get( list.size() - 1 );
			}
			else if (obj instanceof String) {
				ret = obj.toString();
			}
		}
		return ret;
	}

	private void addValue(List<String> list, String value) {
		if (null == list || Utility.isEmpty( value ))
			return;

		// remove duplicate nodes
		String v = value.toLowerCase();
		for (String l : list) {
			if (l.toLowerCase().indexOf( v ) > -1) {
				return;
			}
		}

		String ts;
		for (Iterator<String> it = list.iterator(); it.hasNext();) {
			ts = it.next().toLowerCase();
			if (v.indexOf( ts ) > -1) {
				it.remove();
			}
		}

		list.add( value );
	}

	public Map<String, Object> getMap() {
		return whoisMap;
	}

	public boolean contains(String key) {
		if (get( key ) != null)
			return true;
		return false;
	}

	@SuppressWarnings("unchecked")
	public boolean isEmpty() {
		if (whoisMap.isEmpty())
			return true;

		if (Utility.isEmpty( ( List<String> ) get( "rawdata" ) ))
			return true;

		return false;
	}

	public boolean isNotEmpty() {
		return !isEmpty();
	}

}
