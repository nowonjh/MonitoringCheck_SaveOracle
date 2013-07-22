/**
 * IGLOO Security Inc.
 * Created on 2006. 10. 10
 * by wizver
 */
package com.igloosec.db;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

import org.apache.ibatis.datasource.pooled.PooledDataSource;
import org.apache.log4j.Logger;
import org.araqne.logdb.client.LogDbClient;

import com.igloosec.LogManager;
import com.igloosec.common.CommonUtil;

/**
 * @author JH
 */
public class DBConnectionManager {
	Logger logger = LogManager.getInstance().getLogger("monitoringCheck.db");
	
	private static DBConnectionManager instance;
	public static final String DB_1 = "monitoringCheck";
	private Properties db1Props;
	private PooledDataSource db1DataSource;
	static {
		if (instance == null)
			instance = new DBConnectionManager();
	}

	private DBConnectionManager() {
		try {
			File file = new File(System.getProperty("is.home"), "/conf/extrim.properties");
			db1Props = new Properties();
			db1Props.load(new FileInputStream(file));

			String driverName = db1Props.getProperty("JDBC.Driver");
 			String dbURL = db1Props.getProperty("JDBC.ConnectionURL");
 			String userid = db1Props.getProperty("JDBC.Username");
 			String passwd = db1Props.getProperty("JDBC.Password");
 			int maxActive = Integer.parseInt(db1Props.getProperty("Pool.MaximumActiveConnections", "10"));
 			int maxIdle = Integer.parseInt(db1Props.getProperty("Pool.MaximumIdleConnections", "5"));
			
			db1DataSource = new PooledDataSource(driverName, dbURL, userid, passwd);
			db1DataSource.setPoolMaximumActiveConnections(maxActive);
			db1DataSource.setPoolMaximumIdleConnections(maxIdle);
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}
	}

	public static DBConnectionManager getInstance() {
		return instance;
	}
	
	

	public void freeConnection(LogDbClient client) {
		try {
			if (client != null && !client.isClosed()) {
				client.close();
			}
		} catch (IOException e) {
			logger.error("araqne client close error", e);
		}
	}

	public void freeConnection(Connection con) {
		try {
			if(con != null) {
				con.commit();
				con.close();
			}
		} catch (Exception e) {
			if(con != null) {
				try { con.commit(); con.close(); } catch (SQLException e1) { ; }
			}
			logger.error(e.getMessage(), e);
		}
	}
	
	public LogDbClient getQueryClient(String mgr_ip) {
		LogDbClient client = null;
		try {
			String dbURL = mgr_ip;
			int dbPORT = Integer.parseInt(db1Props.getProperty("araqne.port"));
			String userid = db1Props.getProperty("araqne.username");
			String passwd = db1Props.getProperty("araqne.password");
			
			client = new LogDbClient();
			if (CommonUtil.portIsOpen(dbURL, dbPORT, 1500)) {
				client.connect(dbURL, dbPORT, userid, passwd);
			}
			else {
				logger.warn(mgr_ip + " is not alive");
				client = null;
			}
		} catch (Exception e) {
			logger.error(mgr_ip + " : araqne connect failed", e);
			client = null;
		}
		return client;
	}

	public Connection getConnection() {
		return getConnection(DB_1);
	}

	public Connection getConnection(String name) {
		Connection con = null;
		try {
			if(DB_1.equals(name)){
				con = db1DataSource.getConnection();
			}
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}

		return con;
	}
	
	public Connection getNormalConnection(String name) {
		Connection con = null;
		if(DB_1.equals(name)) {
			String driverName = db1Props.getProperty("JDBC.Driver");
			String dbURL = db1Props.getProperty("JDBC.ConnectionURL");
			String userid = db1Props.getProperty("JDBC.Username");
			String passwd = db1Props.getProperty("JDBC.Password");
			try {
				Class.forName(driverName);
				con = DriverManager.getConnection(dbURL, userid, passwd);
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}
		return con;
	}
}