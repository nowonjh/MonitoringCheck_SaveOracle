package com.igloosec.common;

import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.araqne.logdb.client.TableInfo;
import org.json.simple.JSONObject;
import com.igloosec.CacheManager;
import com.igloosec.RuleInfoVO;
import com.igloosec.db.DBHandler;

/**
 * Araqne에 사용되는 공통 쿼리 메소드
 * @author JH
 *
 */
public class CommonQuery {
	
	/**
	 * exe_query 에서 정규식으로 group by 되는 컬럼을 찾는다.
	 * @param exe_query_group
	 * @return
	 */
	public static List<String> getWhereColumn(String exe_query_group) {
		List<String> result = new LinkedList<String>();
		String where_column = "";
		Pattern pattern = Pattern.compile("(|\\s)stats\\scount\\sby\\s.+?\\|");
		Matcher match_regxp = pattern.matcher(exe_query_group);
		while(match_regxp.find()) {
			result = new LinkedList<String>();
			where_column = match_regxp.group().replaceAll("(\\||stats\\scount\\sby|\\s)", "");
		}
		for(String col : where_column.split(",")){
			if(!"".equals(col)){
				result.add(col.trim());
			}
		}
		
		return result;
	}
	

	/**
	 * 쿼리를 파라미터로 받아 테이블 이름을 반환한다.
	 * @param exe_query
	 * @return
	 */
	public static String getTableName(String exe_query) {
		Pattern pattern = Pattern.compile("\\ssecure_event\\s|\\sresource_event\\s|\\ssystem_event\\s");
		Matcher match_regxp = pattern.matcher(exe_query);
		String table_name = "";
		
		while(match_regxp.find()) {
			table_name = match_regxp.group().replaceAll("\\s", "");
			break;
		}
		return table_name;
	}
	/**
	 * 실제 수행될 Araqne 쿼리
	 * @param exe_query
	 * @param stime
	 * @param table_list
	 * @param table_name
	 * @param table_list
	 * @param param
	 * @return
	 */
	
	//makeQuery(exe_query, stime, etime, origin_type, manager_agent, param)
	public static String makeQuery(RuleInfoVO rule, String exe_query, String stime, String etime, List<String> table_list) {
		JSONObject param = rule.getParam();
		String table_name = CommonQuery.getTableName(exe_query);
		
		for(String key : ((Map<String, String>)param).keySet()){
			exe_query = exe_query.replaceFirst("\\$\\{" + key + "\\}", (param.get(key) == null ? 0 : param.get(key)) + "");
		}
		
		exe_query = exe_query.replaceAll("\\s+", " ").replaceAll("(|\\s)\\|(|\\s)", " | ");
		String[] query_split = exe_query.split("\\|");
		String result_query = "";
		String index_str = "";
		 
		int insertEventTime = 0;
		for(String part : query_split){
			if(part.trim().matches("(^fulltext|^firewall|^attack|^mail|^web|^other).*")){
				part = part.replaceFirst("^fulltext|^firewall|^attack|^mail|^web|^other", "fulltext2 from=? to=? index");
			}
			else if(part.trim().startsWith("search") && insertEventTime++ == 0){
				index_str = createIndexDelimiter(new StringBuffer(part)).toString();

				part += " and (event_time >= ? and event_time < ?) ";
			}
			result_query += part + "|";
		}
		String tables = CommonUtil.listToString(table_list, "", ",");
		index_str = index_str.trim().replaceAll("^search", "").trim();
		index_str = index_str.trim().replaceAll("^and\\s|\\sand$|^and$", "").trim();
		
		if(index_str.length() == 0){
			result_query = result_query.replaceFirst("^fulltext2", "table");
			result_query = result_query.replaceFirst("index", "");
			result_query = result_query.replaceFirst(table_name, tables);
		}
		else {
			result_query = result_query.replaceFirst("index", index_str);
			result_query = result_query.replaceFirst(table_name, "from " + tables);
		}
		
		result_query = result_query.replaceAll("\\|$", "");
		result_query = result_query.replaceFirst("\\?", stime.replaceAll("\\s", ""));
		result_query = result_query.replaceFirst("\\?", etime.replaceAll("\\s", ""));
		result_query = result_query.replaceFirst("\\?", "\"" + stime + "\"");
		result_query = result_query.replaceFirst("\\?", "\"" +etime + "\"");
		result_query = result_query.replaceAll("\\s+", " ");
		
		return result_query;
	}

	/**
	 *  모니터링 룰에 할당된 그룹에 속해있는 에이젼트 IP 를 구함.
	 * @param origin_type
	 * @param group_name
	 * @return
	 */
	public static List<String> getTableList(String dbname, String origin_type, String table_name, List<String> agent_list, String group_name, String user_id) {
		String where = "";
		String query = "";
		
		for(String type : origin_type.split(",")){
			type = type.toLowerCase().trim();
			if("www".equals(type)){
				type = "web";
			}
			else if("unknown".equals(type)){
				type = "";
			}
			where += "lower(product) like '%" + type + "%' or ";
		}
		where = where.replaceAll("\\sor\\s$", "");
		
		if(agent_list.size() > 0){
			where = "(" + where + ") and agent_ip in (";
			for(String agent_ip : agent_list){
				agent_ip = agent_ip.trim().toLowerCase();
				where += "'" + agent_ip + "', ";
			}
			where += "'')";
		}
		
		if("-".equals(group_name)){
			query = "select id, agent_ip, product from agent_info_list WHERE " + where;
		}
		else {
			query = "select id, agent_ip, product from agent_info_list WHERE (" + where + ") AND id IN (SELECT agent_id FROM monitor_agent_list WHERE group_name = '" + group_name + "')";
		}
		
		Map<String, TableInfo> tableMap = CacheManager.getInstance().getTableMap();
		String[][] data = new DBHandler().getNColumnData(dbname, query);
		
		List<String> table_list = new LinkedList<String>();
		for(String[] agent : data){
			TableInfo tableInfo = tableMap.get(table_name + "_" + agent[0]);
			if(tableInfo != null && (tableInfo.getMetadata().get("logparser") != null || tableInfo.getMetadata().get("parser") != null)){
				table_list.add(table_name + "_" + agent[0]);
			}
		}
		
		return table_list ;
	}
	
	
	public static String getEventListQuery(String exe_query, JSONObject resultFilter, String stime, String etime, List<String> table_list, String fields) {
		String result = "";
		String indexes = "";
		Pattern pattern = Pattern.compile("^fulltext.+?\\|");
		Matcher matcher = pattern.matcher(exe_query);
		
		while(matcher.find()) {
			indexes = matcher.group().replaceAll("^fulltext.+?to=\\w{1,}|\\sfrom\\s.*", "");
		}
		
		String search = "";
		
		pattern = Pattern.compile("\\|(\\s|)search\\s.+?\\|");
		matcher = pattern.matcher(exe_query);
		
		while(matcher.find()) {
			search = matcher.group().replaceAll("(^\\||\\|$)", "");
			break;
		}
		
		
		String filter_str = "";
		for(Map<String, Object> filter_map : ((List<Map<String, Object>>)resultFilter.get("filter"))){
			
			int index = 0;
			for(String column : filter_map.keySet()){
				
				if(filter_str.length() == 0){
					filter_str += "(";
				}
				else if(index == 0) {
					filter_str += "(";
				}
				
				filter_str += column + " == \"" + filter_map.get(column) + "\" and ";
				index++;
			}
			filter_str = filter_str.replaceAll("\\sand\\s$", "");
			
			if(filter_str.length() > 0){
				filter_str += ") or ";
			}
		}
		filter_str = filter_str.replaceAll("\\sor\\s$", "");
		
		String add_index = CommonQuery.createIndexDelimiter(new StringBuffer(filter_str)).toString();
		List<String> lookup_script = CommonQuery.getLookupScript(exe_query);
		String lookup_query = "";
		for(String lookup : lookup_script){
			lookup_query += lookup + " | ";
		}
		lookup_query = lookup_query.replaceAll("\\s\\|\\s$", "");
		
		result =  "fulltext2 from=? to=? " + indexes + (add_index.length() > 0 ? " and (" + add_index + ")" : "") + " from " + CommonUtil.listToString(table_list, "", ",") +
				(lookup_query.length() == 0 ? "" : " | " + lookup_query ) +
				" | " + search + (filter_str.length() > 0 ? " and (" + filter_str + ")" : "") + " | fields " + fields;
		result = result.replaceFirst("\\?", stime.replaceAll("\\s", ""));
		result = result.replaceFirst("\\?", etime.replaceAll("\\s", ""));
		return result;
	}
	

	/**
	 * 사용자정의분석 룰의 조건부분을 받아
	 * Araqne index String 으로 가공해 리턴한다.
	 * @param str
	 * @return
	 */
	public static StringBuffer createIndexDelimiter(StringBuffer str) {
		boolean ip_split = Boolean.parseBoolean(CacheManager.getInstance().getProperties().getProperty("araqne.ipsplit", "true"));
		if(str.length() == 0){
			return str;
		}
		
		Map<String, String> searchMap = new LinkedHashMap<String, String>();

		String delimiter = "[!\"#$%&'\\(\\)\\[\\]{}<>*+,-\\./\\:;=?@\\^_`|~ ]";
		Pattern pattern = Pattern.compile("[a-zA-Z1-9_]{1,}(\\s+|)==(\\s+|)\".+?\"");
		Matcher matcher = pattern.matcher(str);
		
		StringBuffer indexes = new StringBuffer(str);
		
		while(matcher.find()) {
			String group = matcher.group();
			String[] arr = group.split("==");
			
			if(arr.length != 2 || "\"*\"".equals(arr[1].trim())){
				indexes.replace(indexes.lastIndexOf(group), indexes.lastIndexOf(group) + group.length(), "");
			}
			else {
				searchMap.put(arr[1].trim(), arr[0].trim());
				group = group.replaceAll("\".+?\"", "");
				
				if(indexes.lastIndexOf(group) > -1){
					indexes.replace(indexes.lastIndexOf(group), indexes.lastIndexOf(group) + group.length(), "");
				}
			}
		}
		
		/* in(xxx, "xxxx") 형태 파싱*/
		pattern = Pattern.compile("in(\\s+|)\\([a-zA-Z_]{1,}.+?\\)");
		matcher = pattern.matcher(str);
		while(matcher.find()) {
			String in = matcher.group();
			String[] arr = in.replaceAll("^in\\(|\\)$", "").split(",");
			
			int arr_length = arr.length;
			for(int i = 1; i < arr_length; i++){
				searchMap.put(arr[i].trim(), arr[0].trim());
			}
			String trans_in = CommonUtil.arrayToString(in.replaceAll("in(\\s+|)\\([a-zA-Z0-9_]{1,},|\\)", "").split(",") , "", " or ").toString();
			
			if(!trans_in.contains("\"*\"")){
				if(indexes.lastIndexOf(in) > -1){
					indexes.replace(indexes.lastIndexOf(in), indexes.lastIndexOf(in) + in.length() + 1, "(" + trans_in + ")");
				}
			}
			else {
				if(indexes.lastIndexOf("and " + in) > -1){
					indexes.replace(indexes.lastIndexOf("and " + in), indexes.lastIndexOf("and " + in) + (("and" + in).length() + 1), "");
				}
				else if (indexes.lastIndexOf("or " + in) > -1){
					indexes.replace(indexes.lastIndexOf("or " + in), indexes.lastIndexOf("or " + in) + (("or" + in).length() + 1), "");
				}
				else {
					if(indexes.lastIndexOf(in) > -1){
						indexes.replace(indexes.lastIndexOf(in), indexes.lastIndexOf(in) + in.length() + 1, "");
					}
				}
			}
		}
		
		if(searchMap.size() > 0){
			pattern = Pattern.compile("\".+?\"");
			matcher = pattern.matcher(str);
			while(matcher.find()) {
				String group = matcher.group();
				
				String tmp_group = group;
				if(group.split(delimiter).length > 0){
					if(searchMap.get(group).equals("ip") || 
							searchMap.get(group).equals("url") || 
							searchMap.get(group).equals("port") ||
							searchMap.get(group).equals("id") ||
							searchMap.get(group).equals("email") ||
							searchMap.get(group).equals("name")
							){
						if(indexes.lastIndexOf(tmp_group) > -1){
							indexes.replace(indexes.lastIndexOf(tmp_group), indexes.lastIndexOf(tmp_group) + tmp_group.length(), "");
						}
						continue;
					}
					
					String tmp_index = "";
					if(!ip_split && 
							(searchMap.get(group).equals("s_info") || 
							searchMap.get(group).equals("d_info") || 
							searchMap.get(group).equals("terminal") || 
							searchMap.get(group).equals("origin"))){
						tmp_index = tmp_group;
						
						if(indexes.lastIndexOf(tmp_group) > -1){
							indexes.replace(indexes.lastIndexOf(tmp_group), indexes.lastIndexOf(tmp_group) + tmp_group.length(), tmp_index);
						}
					}
					else {
						for(String shard : group.split(delimiter)){
							if(shard.length() > 0){
								tmp_index += "\"" + shard + "\" and ";
							}
						}
						tmp_index = tmp_index.replaceAll("\\sand\\s$", "");
						if(tmp_index.length() > 0){
							if(indexes.lastIndexOf(tmp_group) > -1){
								indexes.replace(indexes.lastIndexOf(tmp_group), indexes.lastIndexOf(tmp_group) + tmp_group.length(), "(" + tmp_index + ")");
							}
						}
						else {
							if(indexes.lastIndexOf(tmp_group) > -1){
								indexes.replace(indexes.lastIndexOf(tmp_group), indexes.lastIndexOf(tmp_group) + tmp_group.length(), "");
							}
						}
					}
				}
			}
		}
		
		pattern = Pattern.compile("\\w{1,}?\\(.+?\\)");   //isnotnull() 등 함수 제외
		matcher = pattern.matcher(indexes.toString());
		while(matcher.find()) {
			String match_str = matcher.group();
			if(indexes.lastIndexOf(match_str) > -1){
				indexes.replace(indexes.lastIndexOf(match_str), indexes.lastIndexOf(match_str) + match_str.length(), "");
			}
		}
		
		pattern = Pattern.compile("(\\s+|)(and|or)(\\s+|)$");   //and or
		matcher = pattern.matcher(indexes.toString());
		while(matcher.find()) {
			String match_str = matcher.group();
			if(indexes.lastIndexOf(match_str) > -1){
				indexes.replace(indexes.lastIndexOf(match_str), indexes.lastIndexOf(match_str) + match_str.length(), "");
			}
		}
		
		return indexes;
	}
	
	/**
	 * 사용자정의분석 룰에서 lookup 스크립트를 찾아 리턴한다.
	 * @param exe_query
	 * @return
	 */
	public static List<String> getLookupScript(String exe_query) {
		List<String> result = new LinkedList<String>();
		Pattern pattern = Pattern.compile("lookup\\s.+?\\|");
		Matcher matcher = pattern.matcher(exe_query);
		
		while(matcher.find()) {
			result.add(matcher.group().replaceAll("\\|$", ""));
		}
		return result;
	}


	public static String changeResultToString(Vector<Map<String, Object>> braket_query_result, List<String> column_list){
		StringBuffer result = new StringBuffer();
	
		if(column_list.size() > 1){
			for(Map<String, Object> row : braket_query_result){
				for(String col : column_list){
					result.append(col + " == \"" + row.get(col) + "\" and ");
				}
			}
		}
		else {
			for(Map<String, Object> row : braket_query_result){
				for(String col : column_list){
					result.append("\"" + row.get(col) + "\",");
				}
				
			}
		}
		
		if(result.length() == 0){
			result.append("\"\"");
		}
		else {
			result.delete(result.length() - ",".length(), result.length());
		}
		return result.toString();
	}


	/**
	 * exe_query 에서 category 를 정규식으로 찾는다
	 * @param exe_query_group
	 * @return
	 */
	public static String getCategoryCode(String category) {
		if(category.split(",").length > 1){
			return "ALL";
		}
		String result = "";
		if("attack".equals(category.toLowerCase())){
			result = "E002";
		}
		else if("firewall".equals(category.toLowerCase())){
			result = "E001";
		}
		else if("mail".equals(category.toLowerCase())){
			result = "E004";
		}
		else if("www".equals(category.toLowerCase()) || "web".equals(category.toLowerCase())){
			result = "E008";
		}
		else if("other".equals(category.toLowerCase())){
			result = "ALL";
		}
		else {
			result = "E000";
		}
		return result;
	}
}
