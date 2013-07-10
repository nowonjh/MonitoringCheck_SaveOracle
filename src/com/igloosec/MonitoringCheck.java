package com.igloosec;

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.araqne.logdb.client.IndexInfo;
import org.araqne.logdb.client.LogDbClient;
import org.araqne.logdb.client.TableInfo;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import com.igloosec.common.CommonQuery;
import com.igloosec.common.CommonUtil;
import com.igloosec.db.DBConnectionManager;
import com.igloosec.db.DBHandler;

/**
 * 사용자가 등록한 모니터링 항목을 
 * 주기적으로 쿼리를 수행시켜 결과를 DB에 입력해준다.
 * @author JH
 *
 */
public class MonitoringCheck extends Module {
	List<Map<String, String>> rule_list;
	Map<String, TableInfo> tableMap;
	Map<String, IndexInfo> indexMap;
	
	boolean certLicence = false;
	CertReciept cr;
	
	
	/**
	 * 생성자 - 10분에 한번씩 스케쥴을 수행
	 */
	private MonitoringCheck(){
		super("monitoringCheck.log", "monitoringCheck", "[Link모듈-MonitoringCheck]", 5);
		cr = new CertReciept(super.DB_NAME, "monitoringCheck.log");
		certLicence = cr.checkCertLicence();
		if(certLicence){
			logger.debug("Cert licence file exist");
		}
	}
	
	@Override
	protected void init() {
		tableMap = new LinkedHashMap<String, TableInfo>();
		indexMap = new LinkedHashMap<String, IndexInfo>();
		synchronized (this) {
			getRuleList();
			getTableList();
		}
	}
	
	/**
	 * Araqne Table 및 index 정보를 갱신한다.
	 */
	private void getTableList() {
		String query = "select mgr_ip from agent_info_list group by mgr_ip";
		String[] mgr_list = new DBHandler().getOneColumnData(super.DB_NAME, query);
		

		
		for(String mgr_ip : mgr_list){
			LogDbClient client = DBConnectionManager.getInstance().getQueryClient(mgr_ip);
			if(client == null){
				continue;
			}
			
			List<TableInfo> listTables = new LinkedList<TableInfo>();
			List<IndexInfo> listIndexs = new LinkedList<IndexInfo>();
			try {
				listTables = client.listTables();
				listIndexs = client.listIndexes(null);
			} catch (IOException e) {
				logger.error(e.getMessage());
			}
			
			for(Iterator<TableInfo> iter = listTables.iterator();iter.hasNext();){
				TableInfo table = iter.next();
				tableMap.put(table.getName(), table);
			}
			
			for(Iterator<IndexInfo> iter = listIndexs.iterator();iter.hasNext();){
				IndexInfo index = iter.next();
				indexMap.put(index.getIndexName(), index);
			}
		}
	}

	/**
	 * 모니터링에 등록된 항목을 체크하고
	 * 저장된 쿼리에 현재 시간과 -주기를 넣어주고
	 * 쿼리를 수행시켜 나온 결과값을 DB에 입력해준다.
	 */
	@Override
	protected void excute() throws Exception {
		Calendar cal = Calendar.getInstance();

		for(Iterator<Map<String, String>> iter = rule_list.iterator();iter.hasNext();){
			final Map<String, String> rule = iter.next();
			Thread t = new Thread(){
				public void run(){
					analysis(rule);
				}
			};
			t.start();
		}
		// 매 1분 마다 모니터링 리스트를 갱신
		if(cal.get(Calendar.SECOND) < 5){
			synchronized (rule_list) {
				getRuleList();
				getTableList();
			}
		}
		if(cal.get(Calendar.MINUTE) == 0 && cal.get(Calendar.SECOND) == 0){
			cleanTable();
		}
	}

	/**
	 * 링크되지 않아있는 테이블들을 모두 삭제한다.
	 */
	private void cleanTable() {
		String query = "select table_name from user_tables where table_name like upper('is_monitor_%')";
		String[] data = new DBHandler().getOneColumnData(super.DB_NAME, query);
		
		
		
		
		
	}

	/**
	 * 모니터링 룰 리스트를 전역Map에 보관한다.
	 */
	private void getRuleList() {
		String query = "SELECT a.id, a.rule_id, a.category, a.origin_type, a.title, a.description, a.CYCLE, a.RANGE, " +
				"a.DELAY, a.param, a.agent_list, a.group_name, a.user_id, a.correlation, b.exe_query, a.idate " +
				"FROM is_user_defined_monitor a JOIN is_user_defined_rule b ON a.rule_id = b.id";
		String[][] data = new DBHandler().getNColumnData(super.DB_NAME, query);
		
		rule_list = new LinkedList<Map<String, String>>();
		for(String[] row : data){
			Map<String, String> rule = new LinkedHashMap<String, String>();
			rule.put("monitor_id",	row[0]);
			rule.put("rule_id",		row[1]);
			rule.put("category",	row[2]);
			rule.put("origin_type",	row[3]);
			rule.put("title",		row[4]);
			rule.put("description",	row[5]);
			rule.put("cycle",		row[6]);
			rule.put("range",		row[7]);
			rule.put("delay",		row[8]);
			rule.put("param",		row[9]);
			rule.put("manager_agent",	row[10]);
			rule.put("group_name",	row[11]);
			rule.put("user_id", 	row[12]);
			rule.put("correlation",	row[13]);
			rule.put("exe_query",	row[14]);
			rule.put("idate",	row[15]);
			rule_list.add(rule);
		}
	}

	/**
	 * 현재 시간이 분석을 수행해야하는 시간인지 체크한다.
	 * @param range
	 * @param endCal
	 */
	private boolean checkAnalysisTime(int cycle, Calendar endCal) {
		long current = 0;
		if(cycle >= 86400){
			current = endCal.getActualMaximum(Calendar.DAY_OF_YEAR) * 24 * 60 * 60 + 
					endCal.get(Calendar.HOUR_OF_DAY) * 60 * 60 + 
					endCal.get(Calendar.MINUTE) * 60 + 
					endCal.get(Calendar.SECOND);
		}
		else {
			current = endCal.get(Calendar.DAY_OF_MONTH) * 24 * 60 * 60 +
					endCal.get(Calendar.HOUR_OF_DAY) * 60 * 60 + endCal.get(Calendar.MINUTE) * 60 + endCal.get(Calendar.SECOND);
		}
		
		if(current % cycle == 0){
			return true;
		}
		else {
			return false;
		}
	}
	
	/**
	 * 실제 분석을 수행
	 * @param row
	 */
	public void analysis(Map<String, String> rule) {
		Calendar startCal = Calendar.getInstance();
		Calendar endCal = Calendar.getInstance();
		startCal.set(Calendar.MILLISECOND, 0);
		endCal.set(Calendar.MILLISECOND, 0);
		
		/* 시간이 지연될 경우를 대비해 정확한 시간으로 변경 */
		int startSeconds = startCal.get(Calendar.SECOND);
		int endSeconds = endCal.get(Calendar.SECOND);
		if(startSeconds % 5 != 0 || endSeconds % 5 != 0){
			startCal.set(Calendar.SECOND, startSeconds - (startSeconds % 5));
			endCal.set(Calendar.SECOND, endSeconds - (endSeconds % 5));
		}
		
		int cycle = CommonUtil.getTime(rule.get("cycle"));
		int range = CommonUtil.getTime(rule.get("range"));
		int delay = CommonUtil.getTime(rule.get("delay"));
		
		startCal.add(Calendar.SECOND, -delay);
		endCal.add(Calendar.SECOND, -delay);
		
		if(!checkAnalysisTime(cycle, endCal)) {
			return;
		}
		
		startCal.add(Calendar.SECOND, -range);
		
		String monitor_id = rule.get("monitor_id");
		String title = rule.get("title");
		String exe_query = rule.get("exe_query");
		String param = rule.get("param");
		String origin_type = rule.get("origin_type");
		String group_name = rule.get("group_name");
		String user_id = rule.get("user_id");
		String stime = new SimpleDateFormat("yyyyMMdd HHmmss").format(startCal.getTime());
		String etime = new SimpleDateFormat("yyyyMMdd HHmmss").format(endCal.getTime());
		JSONObject manager_agent = (JSONObject) JSONValue.parse(rule.get("manager_agent"));
		List<String> agent_list = (List<String>) manager_agent.get("agent_list");
		String mgr_ip = (String) manager_agent.get("mgr_ip");
		
		String table_name = CommonQuery.getTableName(exe_query);
		List<String> column_list = CommonQuery.getWhereColumn(exe_query);
		
		logger.debug("*** [" + title + "] start ***");
		long rule_stime = System.currentTimeMillis();
		
		String query = CommonQuery.getTablesQuery(origin_type, agent_list, group_name, user_id);
		String[][] data = new DBHandler().getNColumnData(super.DB_NAME, query);
		
		List<String> table_list = new LinkedList<String>();
		for(String[] agent : data){
			TableInfo tableInfo = tableMap.get(table_name + "_" + agent[0]);
			if(tableInfo != null && (tableInfo.getMetadata().get("logparser") != null || tableInfo.getMetadata().get("parser") != null)){
				table_list.add(table_name + "_" + agent[0]);
			}
		}
		
		if(table_list.size() == 0){
			logger.error("[" + title + "] not exist agent : origin_type=" + origin_type + " group_name=" + group_name);
			return;
		}
		
		exe_query = CommonQuery.makeQuery(exe_query, stime, etime, table_name, table_list, param);
		
		Vector<Map<String, Object>> resultData = new Vector<Map<String,Object>>();

		if(exe_query != null){
			resultData = new DBHandler().getNColumnMapAraqne(super.DB_NAME, mgr_ip, exe_query);
		}
		
		if(resultData.size() == 0){
			query = "insert into is_user_defined_monitor_log(id, event_time, event_count, idate) values " +
					"(" + monitor_id + ", '" + etime + "', 0, sysdate)";
		}
		else {
			try {
				if("secure_event".equals(table_name)){
					JSONObject resultFilter = CommonUtil.getResultFilter(resultData, column_list);
					
					String filter = resultFilter.toJSONString();
					int total_cnt = Integer.parseInt(resultFilter.get("total_cnt") + "");
					query = "insert into is_user_defined_monitor_log(id, event_time, event_count, filter, idate) values " +
							"(" + monitor_id + ", '" + etime + "', " + total_cnt + ", '" + filter + "', sysdate)";

					/* 분석조건에 걸림 */
					if(total_cnt > 0){
						saveResultFile(mgr_ip, monitor_id, exe_query, stime, etime, resultFilter, table_name, table_list);
						/* 침해대응 라이센스 파일 존재 */
						if(certLicence){
							cr.transferCert(title, exe_query, filter, table_name);
						}
					}
				}
				else if("resource_event".equals(table_name)){
					JSONObject resultFilter = CommonUtil.getResultFilter(resultData, column_list);
					String filter = resultFilter.toJSONString();
					int total_cnt = Integer.parseInt(resultFilter.get("total_cnt") + "");
					query = "insert into is_user_defined_monitor_log(id, event_time, event_count, filter, idate) values " +
							"(" + monitor_id + ", '" + etime + "', " + total_cnt + ", '" + filter + "', sysdate)";
					if(total_cnt > 0){
						saveResultFile(mgr_ip, monitor_id, exe_query, stime, etime, resultFilter, table_name, table_list);
					}
				}
			} catch (ParseException e) {
				logger.error(e);
			}
			new DBHandler().excuteUpdate(super.DB_NAME, query);
			printMemoryUsage();
			logger.debug("*** [" + title + "] elapsed time : " + ((System.currentTimeMillis() - rule_stime) / 1000.0) + " ms ***");
		}
	}

	
	/**
	 * 분석결과에 따른 근거이벤트를 파일로 저장한다.
	 * @param id
	 * @param exe_query
	 * @param etime
	 * @param resultFilter
	 * @param table_name
	 * @param table_list 
	 */
	private void saveResultFile(String mgr_ip, String id, String exe_query, String stime, String etime, JSONObject resultFilter, String table_name, List<String> table_list) throws ParseException{
		String fields = "";
		if("secure_event".equals(table_name)){
			fields = "_id, mgr_time, mgr_ip, category, event_time, origin, direction, s_info, s_port, d_info, d_port, protocol, user_id, method, status, evt_size, risk, ext1, ext2, ext3, ext4, ext5, product, note, extend, link, count, raw_event ";
		}
		else if("resource_event".equals(table_name)){
			fields = "_id, event_time, origin, v1, v2, v3, v4, v5, v6, v7, v8 ";
		}
		
		String eventListQuery = CommonQuery.getEventListQuery(exe_query, resultFilter, stime, etime, table_list, fields);
		String yyyyMMdd = "";

		Date date = new SimpleDateFormat("yyyyMMdd HHmmss").parse(etime);
		yyyyMMdd = new SimpleDateFormat("yyyyMMdd").format(date);
		new DBHandler().saveNColumnRDBMS(super.DB_NAME, mgr_ip, id, yyyyMMdd, eventListQuery, fields);
	}


	public static void main(String[] args){
		new MonitoringCheck();
	}
}
