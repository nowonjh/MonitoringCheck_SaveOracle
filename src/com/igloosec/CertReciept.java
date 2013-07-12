package com.igloosec;

import java.io.File;
import java.io.FilenameFilter;
import java.net.UnknownHostException;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;

import com.igloosec.common.CommonUtil;
import com.igloosec.db.DBHandler;

public class CertReciept {
	String DB_NAME;
	Logger logger;
	String use_rdbms = System.getProperty("use.rdbms");
	
	public CertReciept() {

	}
	
	public CertReciept(String dbname, String logger_name) {
		this.DB_NAME = dbname;
		logger = LogManager.getInstance().getLogger(logger_name);
	}
	
	/**
	 * 침해대응 라이센스를 체크한다.
	 * @return
	 */
	public boolean checkCertLicence() {
		/* 침해대응 라이센스 파일 체크 */
		File filePath = new File(System.getProperty("is.home"), "/conf/extrim/license");
		
		if(!filePath.exists()){
			return false;
		}
		
		File[] fList = filePath.listFiles(new FilenameFilter(){
			public boolean accept(File dir, String name) {
				return name.equals("cert.lic");
			}
		});
		
		if(fList.length > 0){
			return true;
		}
		else {
			return false;
		}
	}
	
	/**
	 * 침해사고 이관
	 * @param cert_data
	 * @param title 
	 * @param table_name 
	 * @param filter 
	 * @param exe_query 
	 */
	public void transferCert(String title, String exe_query, String filter, String table_name) {
		DBHandler db = new DBHandler();
		
		String cert_query_where = "";
		String cert_query_hint = "";
		String cert_query = "";
		
		Pattern pattern = Pattern.compile("where\\s.{1,};$");
		Matcher match_regxp = pattern.matcher(exe_query);
		while(match_regxp.find()) {
			cert_query_where = match_regxp.group().replaceAll("^where\\s", "").replaceAll("group\\sby.{1,};$", "").replaceAll("order\\sby.{1,};$", "").replaceAll("^\\s|\\s$", "");
			if(filter != null && !"-".equals(filter)){
				cert_query_where = cert_query_where + " and " + filter.replaceAll("''", "'");
			}
			break;
		}
		
		pattern = Pattern.compile("/\\*.*\\*/");
		match_regxp = pattern.matcher(exe_query);
		while(match_regxp.find()) {
			cert_query_hint = match_regxp.group().replaceAll("^where\\s", "").replaceAll("group\\sby.{1,};$", "").replaceAll("order\\sby.{1,};$", "").replaceAll("^\\s|\\s$", "");
			break;
		}
		
		cert_query = cert_query_hint + " select event_time, origin, s_info, s_port, d_info, d_port, protocol, method, status, ext1, ext2, ext3, ext5 " +
				"from " + table_name + " where " + cert_query_where + " order by event_time mlimit 1;";
		String[][] cert_data = db.getNColumnData(DB_NAME, cert_query);
		
		if(cert_data.length == 0){
			return;
		}
		
		for(String[] row : cert_data){
			String s_info = row[2];
			String s_port = row[3];
			String d_info = row[4];
			String d_port = row[5];
			String origin = row[1];
			long real_src = 0L;
			long real_dst = 0L;
			long real_org = 0L;
			
			try {
				real_src = CommonUtil.getRealIP(s_info);
			} catch (UnknownHostException e) {
				logger.error(e.getMessage(), e);
			}
			try {
				real_dst = CommonUtil.getRealIP(d_info);
			} catch (UnknownHostException e) {
				logger.error(e.getMessage(), e);
			}
			try {
				real_org = CommonUtil.getRealIP(origin);
			} catch (UnknownHostException e) {
				logger.error(e.getMessage(), e);
			}
			
			/* RDBMS 를 사용할 경우 */
			String query = "select cert_seq.nextval from dual";
			String seq = db.getOneColumnData("rdbms", query)[0];
			
			query = "select to_char(sysdate,'yyyy/mm/dd hh24:mi:ss') from dual";
			String sysdate = db.getOneColumnData("rdbms", query)[0];
			
			List<String> queries = new LinkedList<String>();
			query = "insert into cert_receipt(ID, RULE_ID, RCPT_TIME, RCPT_KIND, RCPT_NAME, VIOLATION_TYPE, SRC_IP, REAL_SRC, ORG_IP, DST_IP, " +
					"REAL_DST, DST_PORT, CORR_CNT, GROUP_ID, GROUP_NAME, SRC_ORIGIN, DIRECTION, ESM_LEVEL, VULN_LEVEL, ASSET_LEVEL, RISK_LEVEL, STATUS," +
					"DUPL_CNT, DUPL_TIME, IDATE, ESM_NAME, PARENT_ID, INCIDENT_NUM, USER_ID, MGR_IP, INC_ID, CONF_ID, ATTACK_TYPE, " +
					"COUNTRY_CODE, REAL_ORG, SRC_PORT, PROTOCOL, MAIN_EVENT, GROUP_WEIGHT, VIOLATION_WEIGHT, TITLE,SCOPE, ESM_DB_TIME, IS_DELETED, GROUP_GUBUN) " +
					"values (" + seq + ", null, to_date('" + sysdate + "','yyyy/mm/dd hh24:mi:ss'), 'C', 'IS', null, '" + s_info + "', " + real_src + ", '" + origin + "', " +
					"'" + d_info + "', " + real_dst + ", '" + d_port + "', 1, null, null, (SELECT country_name FROM ip2Location WHERE ip_from >= " + real_src + " AND ip_to <= " + real_src + "), " +
					"'4', 'L', 'L', 'L', 'L', '0', 1, null, to_date('" + sysdate + "','yyyy/mm/dd hh24:mi:ss'), null, null, null, null, null, null, null, null, " +
					"(SELECT country_code FROM ip2Location WHERE ip_from >= " + real_src + " AND ip_to <= " + real_src + "), " + real_org + ", '" + s_port + "', null, '0', " +
					"null, null, '" + title + "', null, null, 'N', null)";
			
			queries.add(query);
			query = "insert into cert_receipt_ipinfo(ID, SRC_GROUP_ID, SRC_GROUP_NAME, SRC_VULN_LEVEL, SRC_ASSET_LEVEL, SRC_RISK_LEVEL, ORG_GROUP_ID, ORG_GROUP_NAME, " +
					"ORG_VULN_LEVEL, ORG_ASSET_LEVEL, ORG_RISK_LEVEL, DST_GROUP_ID, DST_GROUP_NAME, DST_VULN_LEVEL, DST_ASSET_LEVEL, DST_RISK_LEVEL, SRC_GROUP_WEIGHT, " +
					"ORG_GROUP_WEIGHT, DST_GROUP_WEIGHT, SRC_ISBLACK, DST_ISBLACK, SRC_ISPROXY, DST_ISPROXY) " +
					"values (" + seq + ", null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null, null)";
			queries.add(query);
			
			query = "insert into cert_receipt_sub(CERT_ID, SUB_ID, RCPT_TIME, RULE_ID, CONF_ID, ALT_LEVEL, ORG_IP, REAL_ORG, SRC_IP, REAL_SRC, SRC_PORT, DST_IP, " +
					"REAL_DST, DST_PORT, PROTOCOL, INFO_STATUS, CORR_CNT, ESM_NAME, ESM_DB_TIME)" +
					"values (" + seq + ", 1, to_date('" + sysdate + "','yyyy/mm/dd hh24:mi:ss'), null, null, 1, '" + origin + "', " + real_org + ", '" + s_info + "', " + real_src + ", '" + s_port + "', '" + d_info + "', " + real_dst + ", '" + d_port + "', " +
					"null, null, 1, null, null)";
			queries.add(query);
			
			query = "insert into cert_content(id, kind, sub_id, content) values (" + seq + ", '1', 0, '" + title + "')";
			queries.add(query);
			
			db.excuteBatch("rdbms", queries.toArray(new String[0]));
		}
		
		logger.debug("[" + title + "] transferCert.");
	}
}
