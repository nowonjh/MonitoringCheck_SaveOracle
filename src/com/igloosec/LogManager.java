/**
 * IGLOO Security Inc.
 * Created on 2006. 10. 10
 * by wizver 
 */
package com.igloosec;

import java.io.File;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

/**
 *
 * @author wizver
 */
public class LogManager{

	private static LogManager mgr;

	static{
		if(mgr == null)
			mgr = new LogManager();
	}

	private LogManager() {
		File dir = new File(System.getProperty("is.home"), "/conf/link.log4j");
		PropertyConfigurator.configure(dir.getAbsolutePath());
	}

	public static LogManager getInstance() {
		return mgr;
	}

	public Logger getLogger(String name) {
		return Logger.getLogger(name);
	}
}
