package com.igloosec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * 
 * @author wizver
 *
 */
public class CacheManager {
	static Logger logger = LogManager.getInstance().getLogger("monitoringCheck.log");
	
	private static CacheManager instance;
	private Properties config;
	private long configModified;
	private File configFile;
	
	static {
		if(instance == null)
			instance = new CacheManager();
	}
	
	/**
	 * 기본 생성자
	 */
	private CacheManager() {
		initCache();
	}
	
	/**
	 * DB 데이터를 쿼리하여 메모리에 보관한다.
	 */
	private void initCache() {
		config = new Properties();
		configModified = -1L;
		configFile = new File(System.getProperty("is.home"), "/conf/extrim.properties");
	}
	
	public Properties getProperties() {
		if(configModified != configFile.lastModified()) {
			logger.debug("extrim.properties file read...");
			configModified = configFile.lastModified();
			
			try {
				config.load(new FileInputStream(configFile));
			} catch (FileNotFoundException e) {
				logger.error(configFile.getAbsolutePath() + " not found..");
			} catch (IOException e) {
				logger.error(e.getMessage());
			}
		}
		
		return config;
	}
	/**
	 * CacheManager 객체를 구한다.
	 * @return CacheManager 객체
	 */
	public static CacheManager getInstance() {
		return instance;
	}
}
