package com.igloosec;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.json.simple.JSONObject;

import com.igloosec.common.CommonQuery;
import com.igloosec.common.CommonUtil;
import com.igloosec.db.DBHandler;

/**
 * 사용자가 등록한 모니터링 항목을 
 * 주기적으로 쿼리를 수행시켜 결과를 DB에 입력해준다.
 * @author JH
 *
 */
public class MonitoringCheck extends Module {
	boolean certLicence = false;
	CertReciept cr;
	CacheManager cache;
	/**
	 * 생성자 - 10분에 한번씩 스케쥴을 수행
	 */
	private MonitoringCheck(){
		super("monitoringCheck.log", "monitoringCheck", "[Link모듈-MonitoringCheck]", 5);
		cr = new CertReciept(super.DB_NAME, "monitoringCheck.log");
		certLicence = cr.checkCertLicence();
		if(certLicence){
			logger.info("Cert licence file exist");
		}
	}
	
	@Override
	protected void init() {
		cache = CacheManager.getInstance();
		synchronized (this) {
			cache.initRuleList(super.DB_NAME);
			cache.initTableList(super.DB_NAME);
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

		// 매 1분 마다 모니터링 리스트를 갱신
		if(cal.get(Calendar.SECOND) == 0){
			synchronized (cache.getRule_list()) {
				cache.initRuleList(super.DB_NAME);
				cache.initTableList(super.DB_NAME);
			}
		}
		// 한시간에 한번 사용하지 않는 테이블 정리
		if(cal.get(Calendar.MINUTE) == 0 && cal.get(Calendar.SECOND) == 0){
			cleanTable();
		}
		
		
		Map<String, RuleInfoVO> rule_list = cache.getRule_list();
		
		
		for(String rule_key : rule_list.keySet()){
			final RuleInfoVO rule = rule_list.get(rule_key);
			Thread tread = new Thread(){
				public void run(){
					analysis(rule);
				}
			};
			tread.start();
		}
	}

	/**
	 * 링크되어 있지않은 테이블, 보관기간이 지난 테이블을 모두 삭제한다.
	 */
	private void cleanTable() {
		Map<String, RuleInfoVO> rule_list = cache.getRule_list();
		
		String query = "SELECT tables, Count(tables) FROM (select SubStr(table_name, 0, InStr(table_name, '_', 1,3) - 1) tables from user_tables where table_name like upper('is_monitor_%')) GROUP BY tables order by count(tables) desc";
		String[][] data = new DBHandler().getNColumnData(super.DB_NAME, query);
		
		int max_store_cnt = Integer.parseInt(cache.getProperties().getProperty("max.store.cnt", "30"));
		List<String> drop_table_list = new LinkedList<String>();
		
		for(String[] row : data){
			int drop_tables = Integer.parseInt(row[1]) - max_store_cnt;
			if(drop_tables >= 1){
				query = "SELECT table_name FROM (SELECT table_name, ROWNUM rn FROM user_tables WHERE table_name LIKE Upper('" + row[0] + "_%') ORDER BY table_name) WHERE rn <= " + drop_tables;
				String[] tables = new DBHandler().getOneColumnData(super.DB_NAME, query);
				for(String table_name : tables){
					drop_table_list.add("drop table " + table_name + " purge");
				}
			}
			else if (!rule_list.containsKey(row[0].split("_")[2])){
				query = "SELECT table_name, ROWNUM rn FROM user_tables WHERE table_name LIKE Upper('" + row[0] + "_%')";
				String[] tables = new DBHandler().getOneColumnData(super.DB_NAME, query);
				for(String table_name : tables){
					drop_table_list.add("drop table " + table_name + " purge");
				}
			}
		}
		
		if(drop_table_list.size() > 0){
			new DBHandler().excuteBatch(super.DB_NAME, drop_table_list.toArray(new String[0]));
			for(String drop_query : drop_table_list){
				logger.info(drop_query);
			}
			logger.info("drop tables. count : " + drop_table_list.size());
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
	public void analysis(RuleInfoVO rule) {
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
		
		int cycle = rule.getCycle();
		int range = rule.getRange();
		int delay = rule.getDelay();
		
		startCal.add(Calendar.SECOND, -delay);
		endCal.add(Calendar.SECOND, -delay);
		
		if(!checkAnalysisTime(cycle, endCal)) {
			return;
		}
		
		startCal.add(Calendar.SECOND, -range);
		
		String monitor_id			= rule.getMonitor_id() + "";
		String title				= rule.getTitle();
		String exe_query			= rule.getExe_query();
		String origin_type			= rule.getOrigin_type();
		String group_name			= rule.getGroup_name();
		String user_id				= rule.getUser_id();
		JSONObject manager_agent	= rule.getManager_agent();
		
		logger.info("*** [" + title + "] start analysis ***");
		long rule_stime = System.currentTimeMillis();
		
		String stime = new SimpleDateFormat("yyyyMMdd HHmmss").format(startCal.getTime());
		String etime = new SimpleDateFormat("yyyyMMdd HHmmss").format(endCal.getTime());
		
//		String table_name = CommonQuery.getTableName(exe_query);
		List<String> agent_list = (List<String>) manager_agent.get("agent_list");
		String mgr_ip = (String) manager_agent.get("mgr_ip");
		
		while(exe_query.contains("[") && exe_query.contains("]")){
			int start_braket = exe_query.indexOf("[");
			int end_braket = exe_query.indexOf("]");
			
			String braket_query = exe_query.substring(start_braket, end_braket + 1).trim();
			
			while(braket_query.indexOf("[", 1) > -1){
				start_braket = exe_query.indexOf("[", start_braket + 1);
				braket_query = exe_query.substring(start_braket, end_braket + 1).trim();
			}
			
			String tmp_query = braket_query.replaceAll("\\[|\\]", "").trim();
			if(tmp_query.toLowerCase().matches("(^firewall|^attack|^mail|^web|^other).*")){
				origin_type = tmp_query.toLowerCase().split("\\s")[0];
			}
			String table_name = CommonQuery.getTableName(tmp_query);
			List<String> table_list = CommonQuery.getTableList(super.DB_NAME, origin_type, table_name, agent_list, group_name, user_id);
			if(table_list.size() == 0){
				logger.warn("[" + title + "] not exist agent : origin_type=" + origin_type + " group_name=" + group_name);
				return;
			}			
			tmp_query = CommonQuery.makeQuery(rule, tmp_query, stime, etime, table_list);
			Vector<Map<String, Object>> braket_query_result = new DBHandler().getNColumnMapAraqne(super.DB_NAME, mgr_ip, tmp_query);
			
			if(braket_query_result.size() == 0){
				exe_query = null;
				break;
			}
			else {
				List<String> column_list = CommonQuery.getWhereColumn(braket_query);
				String query_result = CommonQuery.changeResultToString(braket_query_result, column_list);
				exe_query = exe_query.replace(braket_query, query_result);
			}
		}
		
		String query = "insert into is_user_defined_monitor_log(id, event_time, event_count, idate) values " +
				"(" + monitor_id + ", '" + etime + "', 0, sysdate)";
		
		if(exe_query != null){
			origin_type	= rule.getOrigin_type();
			if(exe_query.toLowerCase().matches("(^firewall|^attack|^mail|^web|^other).*")){
				origin_type = exe_query.toLowerCase().split("\\s")[0];
			}
			String table_name = CommonQuery.getTableName(exe_query);
			List<String> table_list = CommonQuery.getTableList(super.DB_NAME, origin_type, table_name, agent_list, group_name, user_id);
			
			if(table_list.size() == 0){
				logger.warn("[" + title + "] not exist agent : origin_type=" + origin_type + " group_name=" + group_name);
				return;
			}
			exe_query = CommonQuery.makeQuery(rule, exe_query, stime, etime, table_list);
			Vector<Map<String, Object>> resultData = new Vector<Map<String,Object>>();
			
			resultData = new DBHandler().getNColumnMapAraqne(super.DB_NAME, mgr_ip, exe_query);

			if(resultData.size() > 0){
				List<String> column_list = CommonQuery.getWhereColumn(exe_query);
				
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
			}
		}
		
		new DBHandler().excuteUpdate(super.DB_NAME, query);

		printMemoryUsage();
		logger.info("*** [" + title + "] elapsed time : " + ((System.currentTimeMillis() - rule_stime) / 1000.0) + " ms ***");
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
		String araqne_line = cache.getProperties().getProperty("araqne.line", "line");
		
		String fields = "";
		if("secure_event".equals(table_name)){
			fields = "_id, mgr_time, mgr_ip, category, event_time, origin, direction, s_info, s_port, d_info, d_port, protocol, user_id, method, status, evt_size, risk, ext1, ext2, ext3, ext4, ext5, product, note, extend, link, count, " + araqne_line;
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
