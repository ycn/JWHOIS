package com.jwhois.core;

public interface LineFilter {

	String filterLine(String line);

	String filterHtmlLine(String line);

	boolean skipLine(String line);

	boolean skipHtmlLine(String line);

}
