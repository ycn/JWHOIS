package com.jwhois.core;

public interface Logger {
	public enum LEVEL {
		ERROR, WARN, INFO, DEBUG
	};

	void doLog(LEVEL lv, String info, Exception e);
}
