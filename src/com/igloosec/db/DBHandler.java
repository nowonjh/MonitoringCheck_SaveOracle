/**
 * IGLOO Security Inc.
 * Created on 2006. 10. 10
 * by wizver
 */
package com.igloosec.db;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.sql.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import oracle.jdbc.internal.OraclePreparedStatement;
import org.apache.log4j.Logger;
import org.araqne.logdb.client.LogCursor;
import org.araqne.logdb.client.LogDbClient;
import org.araqne.logdb.client.LogQuery;
import com.igloosec.LogManager;

/**
 * @author JH
 */
public class DBHandler {
	Logger logger = LogManager.getInstance().getLogger("monitoringCheck.db");

	public Vector<Map<String, Object>> getNColumnMapAraqne(String name, String mgr_ip, String query) {
		Vector rowSet = new Vector();
		LogDbClient client = null;
		try {
			client = DBConnectionManager.getInstance().getQueryClient(mgr_ip);
			LogCursor cursor = null;
			try {
				cursor = client.query(query);
				while (cursor.hasNext()) {
					Map<String, Object> o = cursor.next();
					rowSet.addElement(o);
				}
				logger.debug(query);
			} catch (IOException e) {
				logger.error(e.getMessage() + " : error query => " + query, e);
			} finally {
				if (cursor != null) {
					try {
						cursor.close();
					} catch (IOException e) {
						logger.error(e.getMessage(),e);
					}
				}
				DBConnectionManager.getInstance().freeConnection(client);
			}

		} catch (Exception e) {
			logger.error(e.getMessage() + " client is close : " + client.isClosed() + " : error query => " + query, e);
		}
		return rowSet;
	}

	public String[][] getNColumnDataAraqne(String name, String mgr_ip, String query) {
		LogDbClient client = null;
		Vector rowSet = new Vector();
		Vector row = null;
		int colCnt = 0;
		try {
			client = DBConnectionManager.getInstance().getQueryClient(mgr_ip);

			LogCursor cursor = null;
			try {
				cursor = client.query(query);
				logger.debug(cursor.hasNext());
				while (cursor.hasNext()) {
					Map<String, Object> o = cursor.next();
					Set<String> keyset = o.keySet();
					colCnt = keyset.size();
					row = null;
					row = new Vector();

					for (String key : keyset) {
							row.addElement(o.get(key));
					}
					rowSet.addElement(row);
				}

				logger.debug(query);

			} catch (IOException e) {
				logger.error(e.getMessage() + " : error query => " + query, e);
			} finally {
				if (cursor != null) {
					try {
						cursor.close();
					} catch (IOException e) {
					}
				}
				DBConnectionManager.getInstance().freeConnection(client);
			}

		} catch (Exception e) {
			// close(con, stmt, rs);
			 logger.error(e.getMessage() + " : error query => " + query, e);
		}

		logger.debug(rowSet.size());

		String[][] data = new String[rowSet.size()][colCnt];
		for (int i = 0; i < data.length; i++) {
			row = null;
			row = (Vector) rowSet.elementAt(i);
			for (int j = 0; j < colCnt; j++) {
				if (row.elementAt(j) == null) {
					data[i][j] = "-";
				} else {
					data[i][j] = row.elementAt(j).toString().trim();
				}
			}
		}

		return data;
	}

	public String[][] getNColumnData(String name, String query) {
		Connection con = null;
		Statement stmt = null;
		ResultSet rs = null;
		Vector rowSet = new Vector();
		Vector row = null;
		int colCnt = 0;
		try {
			con = DBConnectionManager.getInstance().getConnection(name);
			stmt = con.createStatement();
			rs = stmt.executeQuery(query);
			colCnt = rs.getMetaData().getColumnCount();

			while (rs.next()) {
				row = null;
				row = new Vector();
				for (int i = 0; i < colCnt; i++) {
					row.addElement(rs.getString(i + 1));
				}
				rowSet.addElement(row);
			}

			close(con, stmt, rs);

			logger.debug(query);
		} catch (SQLException e) {
			close(con, stmt, rs);
			logger.error(e.getMessage() + " : error query => " + query, e);
		}

		String[][] data = new String[rowSet.size()][colCnt];
		for (int i = 0; i < data.length; i++) {
			row = null;
			row = (Vector) rowSet.elementAt(i);
			for (int j = 0; j < colCnt; j++) {
				if (((String) row.elementAt(j)) == null) {
					data[i][j] = "-";
				} else {
					data[i][j] = ((String) row.elementAt(j)).trim();
				}
			}
		}

		return data;
	}

	public String[] getOneColumnData(String name, String query) {
		Connection con = null;
		Statement stmt = null;
		ResultSet rs = null;
		Vector row = new Vector();
		try {
			con = DBConnectionManager.getInstance().getConnection(name);
			stmt = con.createStatement();
			rs = stmt.executeQuery(query);

			while (rs.next()) {
				row.addElement(rs.getString(1));
			}

			close(con, stmt, rs);

			logger.debug(query);
		} catch (SQLException e) {
			close(con, stmt, rs);
			logger.error(e.getMessage() + " : error query => " + query, e);
		}

		String[] data = new String[row.size()];
		for (int i = 0; i < data.length; i++) {
			if (row.elementAt(i) == null) {
				data[i] = "-";
			} else {
				data[i] = ((String) row.elementAt(i)).trim();
			}
		}
		return data;
	}

	public boolean excuteUpdate(String name, String query) {
		boolean flag = false;
		Connection con = null;
		Statement stmt = null;
		try {
			con = DBConnectionManager.getInstance().getConnection(name);
			stmt = con.createStatement();
			stmt.executeUpdate(query);
			close(con, stmt, null);
			flag = true;
			logger.debug(query);
		} catch (SQLException e) {
			close(con, stmt, null);
			logger.error(e.getMessage() + " : query is " + query, e);
		}
		return flag;
	}

	
	public boolean excuteBatch(String name, String[] query) {
		boolean flag = false;
		Connection con = null;
		Statement stmt = null;
		try {
			con = DBConnectionManager.getInstance().getConnection(name);
			con.setAutoCommit(false);
			stmt = con.createStatement();
			for (int i = 0; i < query.length; i++) {
				stmt.addBatch(query[i]);
			}
			stmt.executeBatch();
			con.commit();
			close(con, stmt, null);
			flag = true;
		} catch (SQLException e) {
			try {
				con.rollback();
			} catch (SQLException e1) {
				logger.error(e.getMessage(), e);
			}
			close(con, stmt, null);
			logger.error(e.getMessage(), e);
		} finally {
		}

		return flag;
	}


	private void close(Connection con, Statement stmt, ResultSet rs) {
		try {
			if (rs != null) {
				rs.close();
				rs = null;
			}
			if (stmt != null) {
				stmt.close();
				stmt = null;
			}
		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}

		DBConnectionManager.getInstance().freeConnection(con);
	}

	public String getISSeq() {
		String result = null;
		Connection con = null;
		PreparedStatement stmt = null;
		ResultSet rs = null;
		String query = "select is_seq.nextval from dual";
		try {
			con = DBConnectionManager.getInstance().getConnection();
			stmt = con.prepareStatement(query);
			rs = stmt.executeQuery(query);
			rs.next();
			result = rs.getString(1);
			close(con, stmt, rs);
		} catch (SQLException e) {
			close(con, stmt, rs);
			logger.error(e.getMessage(), e);
		}
		return result;
	}

	public void saveNColumnRDBMS(String db_name, String mgr_ip, String id, String yyyyMMdd, String exe_query, String fields) {
		String table_name = "is_monitor_" + id + "_" + yyyyMMdd;
		boolean existTable = existTable(db_name, table_name);
		if(!existTable){
			String query = "CREATE TABLE " + table_name + "(" +
				"id VARCHAR2(32) PRIMARY KEY," +
				"mgr_time VARCHAR2(32)," +
				"mgr_ip VARCHAR2(32)," +
				"category VARCHAR2(4)," +
				"event_time VARCHAR2(32)," +
				"origin VARCHAR2(32)," +
				"direction VARCHAR2(1)," +
				"s_info VARCHAR2(64)," +
				"s_port VARCHAR2(8)," +
				"d_info VARCHAR2(64)," +
				"d_port VARCHAR2(8)," +
				"protocol VARCHAR2(8)," +
				"user_id VARCHAR2(32)," +
				"method CLOB," +
				"status VARCHAR2(8)," +
				"evt_size VARCHAR2(8)," +
				"risk VARCHAR2(1)," +
				"ext1 VARCHAR2(64)," +
				"ext2 VARCHAR2(64)," +
				"ext3 VARCHAR2(64)," +
				"ext4 VARCHAR2(64)," +
				"ext5 VARCHAR2(64)," +
				"product VARCHAR2(64)," +
				"note VARCHAR2(1024)," +
				"extend VARCHAR2(256)," +
				"LINK VARCHAR2(4)," +
				"Count VARCHAR2(4)," +
				"raw_event CLOB)";
			existTable = excuteUpdate(db_name, query);
			query = "CREATE INDEX " + table_name + "_TIME ON " + table_name + "(EVENT_TIME)";
			existTable = excuteUpdate(db_name, query);
		}
		LogDbClient client = DBConnectionManager.getInstance().getQueryClient(mgr_ip);
		
		try {
			
			int query_id = client.createQuery(exe_query);
			client.startQuery(query_id);
			LogQuery q = client.getQuery(query_id);
			int pagesize = 20000;
			int page = 1;
			int loop = 0;
			
			boolean flag = true;
			while (flag) {
				if (loop > 30) {
					loop = 0;
				}

				if (q.getStatus().equalsIgnoreCase("Ended")) {
					long ended_data = q.getLoadedCount() - (pagesize * (page - 1));
					
					if (ended_data > pagesize) {
						Map<String, Object> rows = client.getResult(query_id, (pagesize * (page - 1)), pagesize);
						insert(table_name, db_name, rows, fields, id, yyyyMMdd);
						loop = 0;
						page++;
						continue;
					} else {
						Map<String, Object> rows = client.getResult(query_id, (pagesize * (page - 1)), (int) q.getLoadedCount());
						insert(table_name, db_name, rows, fields, id, yyyyMMdd);
						loop = 0;
					}
					break;
				} else {
					if (q.getLoadedCount() > (pagesize * page)) {
						Map<String, Object> rows = client.getResult(query_id, (pagesize * (page - 1)), pagesize);
						insert(table_name, db_name, rows, fields, id, yyyyMMdd);
						loop = 0;
						page++;
					}
				}
				loop++;
			}
			logger.debug(exe_query);
			client.stopQuery(query_id);
			client.removeQuery(query_id);
		} catch (IOException e) {
			logger.error(e.getMessage(), e);
		}
	}
	
	
	private boolean insert(String table_name, String db_name, Map<String, Object> rows, String fields, String id, String yyyyMMdd) {
		
		Connection con = DBConnectionManager.getInstance().getConnection(db_name);
		PreparedStatement pstmt = null;
		boolean flag = false;
		
		String values = "";
		
		fields = fields.replaceAll("^\\_id\\,", "");
		
		for(int i = 0; i < fields.split(",").length; i++){
			values += "?,";
		}
		values = values.replaceAll("\\,$", "");
		
		try {
			pstmt = con.prepareStatement("insert into " + table_name + "(id," + fields + ") values(?," + values + ")");
			for (Map<String, Object> row : ((ArrayList<Map<String, Object>>) rows.get("result"))) {
				
				try {
					yyyyMMdd = new SimpleDateFormat("yyyyMMdd").format(new SimpleDateFormat("yyyyMMdd HHmmss").parse(row.get("event_time").toString()));
				} catch (ParseException e) {
					logger.error(e.getMessage(), e);
				}
				
				pstmt.setString(1, id + "_" + yyyyMMdd + "_" + row.get("_id"));
				
				int index = 2;
				for(String field : fields.split(",")){
					pstmt.setString(index++, getColumn(row.get(field.trim())));
				}
				try{
					pstmt.executeUpdate();
				} catch (SQLException e){
					if(e.getMessage().contains("ORA-00001")){
						continue;
					}
					else {
						throw e;
					}
				}
			}
			con.commit();
			close(con, pstmt, null);
			flag = true;
		} catch (SQLException e) {
			try {
				con.rollback();
			} catch (SQLException e1) {
				logger.error(e1.getMessage(), e);
			}
			close(con, pstmt, null);
			logger.error(e.getMessage(), e);
		}

		return flag;
		
		
	}
	
	public static String getColumn(Object o) {
		String result = "-";

		if (o == null || "null".equals(o)) {
			return result;
		}

		result = reqFilter(String.valueOf(o));
		
		return result;
	}
	
	public static String reqFilter(String str) {
		str = ascToUtf(str);

		//str = str.replaceAll("--", "");

        return str;
    }
	
	public static String ascToUtf(String str) {
        String returnStr = "";
        if(str == null)
            return returnStr;

        try {
            returnStr = new String(str.getBytes("8859_1"), "UTF-8");
        } catch (UnsupportedEncodingException ue) { ; }

        return returnStr;
    }

	public boolean existTable(String db_name, String table_name){
		String query = "SELECT table_name FROM user_tables WHERE table_name = upper('" + table_name + "')";
		String[][] data = getNColumnData(db_name, query);
		if(data.length > 0){
			return true;
		}
		return false;
	}

	public void saveNColumnRDBMSTest(String db_name, String id) {
		String table_name = "is_monitor_" + id;
		
		logger.debug(db_name + " " + table_name);		
		boolean existTable = existTable(db_name, table_name);
		if(!existTable){
			String query = "CREATE TABLE " + table_name + "(" +
				"id VARCHAR2(32) primary key," +
				"mgr_time VARCHAR2(32)," +
				"mgr_ip VARCHAR2(32)," +
				"category VARCHAR2(4)," +
				"event_time VARCHAR2(32)," +
				"origin VARCHAR2(32)," +
				"direction VARCHAR2(1)," +
				"s_info VARCHAR2(64)," +
				"s_port NUMBER," +
				"d_info VARCHAR2(64)," +
				"d_port NUMBER," +
				"protocol NUMBER," +
				"user_id VARCHAR2(32)," +
				"method clob," +
				"status NUMBER," +
				"evt_size NUMBER," +
				"risk VARCHAR2(1)," +
				"ext1 VARCHAR2(64)," +
				"ext2 VARCHAR2(64)," +
				"ext3 VARCHAR2(64)," +
				"ext4 VARCHAR2(64)," +
				"ext5 VARCHAR2(64)," +
				"product VARCHAR2(64)," +
				"note VARCHAR2(256)," +
				"extend VARCHAR2(256)," +
				"LINK VARCHAR2(4)," +
				"Count NUMBER)";
			existTable = excuteUpdate(db_name, query);
		}
		Connection con = null;
		PreparedStatement pstmt = null;
		try {
			
			con = DBConnectionManager.getInstance().getConnection(db_name);
			con.setAutoCommit(false);
			pstmt = con.prepareStatement("insert into " + table_name + "" +
					"(id, event_time, origin, s_info, s_port, d_info, d_port, protocol, user_id, method, status, ext1, ext2, ext3, ext4, ext5, note ) " +
					"values(?," +
						"'20130101 000000', " +
						"'192.168.150.71', " +
						"'125.186.225.145'," +
						"20000," +
						"'192.168.150.75'," +
						"80," +
						"1, " +
						"'nowonjh', " +
						"?, " +
						"1, " +
						"'ext1', " +
						"'ext2', " +
						"'ext3', " +
						"'ext4', " +
						"'ext5', " +
						"'note')");
			((OraclePreparedStatement)pstmt).setExecuteBatch(1000);
			for(int i = 0; i < 50000; i++){
				
				pstmt.setString(1, id+"_"+i);
				pstmt.setString(2, "method");
				try{
					pstmt.executeUpdate();
				} catch (SQLException e){
					if(e.getMessage().contains("ORA-00001")){
						continue;
					}
					else {
						throw e;
					}
				}
			}
			
			con.commit();
			close(con, pstmt, null);
		} catch (SQLException e) {
			try {
				con.rollback();
			} catch (SQLException e1) {
				logger.error(e1.getMessage(), e);
			}
			close(con, pstmt, null);
			logger.error(e.getMessage(), e);
		} finally {
			logger.debug("finally");
		}
		logger.debug("make insert query");
	}
}