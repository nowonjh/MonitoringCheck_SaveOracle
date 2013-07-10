package com.igloosec.common;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import com.igloosec.CacheManager;


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
	 * @param etime
	 * @param table_name
	 * @param table_list
	 * @param param
	 * @return
	 */
	public static String makeQuery(String exe_query, String stime,String etime, String table_name, List<String> table_list, String param_str) {
		JSONObject param = (JSONObject) JSONValue.parse(param_str);
		for(Iterator<String> iter = param.keySet().iterator();iter.hasNext();){
			String key = iter.next();
			exe_query = exe_query.replaceFirst("\\$\\{" + key + "\\}", param.get(key) + "");
		}
		
		exe_query = exe_query.replaceAll("\\s{1,}", " ");
		String[] query_split = exe_query.split("\\|");
		String result_query = "";
		String indexes = "";
		
		int insertEventTime = 0;
		for(String part : query_split){
			if(part.trim().startsWith("fulltext")){
				part = part.replaceFirst("fulltext", "fulltext2 from=? to=? index from");
			}
			else if(part.trim().startsWith("search") && insertEventTime++ == 0){
				indexes = createIndexDelimiter(part);
				
				part += " and (event_time >= ? and event_time < ?) ";
			}
			result_query += part + "|";
		}
		String tables = CommonUtil.listToString(table_list, "", ",");
		
		indexes = indexes.trim().replaceAll("^search\\s", "");
		result_query = result_query.replaceAll("\\|$", "");
		result_query = result_query.replaceFirst("index", indexes);

		result_query = result_query.replaceFirst("\\?", stime.replaceAll("\\s", ""));
		result_query = result_query.replaceFirst("\\?", etime.replaceAll("\\s", ""));
		result_query = result_query.replaceFirst("\\?", "\"" + stime + "\"");
		result_query = result_query.replaceFirst("\\?", "\"" +etime + "\"");
		result_query = result_query.replaceFirst(table_name, tables);
		result_query = result_query.replaceAll("\\s+", " ");
		
		return result_query;
	}


	/**
	 *  모니터링 룰에 할당된 그룹에 속해있는 에이젼트 IP 를 구함.
	 * @param origin_type
	 * @param group_name
	 * @return
	 */
	public static String getTablesQuery(String origin_type, List<String> agent_list, String group_name, String user_id) {
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
		
//		if(!"-".equals(agent_list) && agent_list.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*")){
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
		
		return query ;
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
		for(Iterator<Map<String, Object>> iter = ((List<Map<String, Object>>)resultFilter.get("filter")).iterator(); iter.hasNext();){
			Map<String, Object> filter_map = iter.next();
			
			int index = 0;
			for(Iterator<String> i = filter_map.keySet().iterator(); i.hasNext();){
				
				String column = i.next();
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
//		if(Integer.parseInt(resultFilter.get("total_cnt") + "") > 0 && filter_str.length() > 0){
//			filter_str += ")";
//		}
		String add_index = CommonQuery.createIndexDelimiter(filter_str);
		
		result =  "fulltext2 from=? to=? " + indexes + (add_index.length() > 0 ? " and (" + add_index + ")" : "") + " from " + CommonUtil.listToString(table_list, "", ",") +
				" | " + search + " and (" + filter_str + ") | fields " + fields;
		result = result.replaceFirst("\\?", stime.replaceAll("\\s", ""));
		result = result.replaceFirst("\\?", etime.replaceAll("\\s", ""));
		return result;
		
	}
	
	public static String createIndexDelimiter(String str) {
		boolean ip_split = Boolean.parseBoolean(CacheManager.getInstance().getProperties().getProperty("araqne.ipsplit", "true"));
		if(str.length() == 0){
			return str;
		}
		
		Map<String, String> searchMap = new LinkedHashMap<String, String>();
		
		String indexes;
		String delimiter = "[^a-zA-Z0-9]";
		Pattern pattern = Pattern.compile("[a-zA-Z_]{1,}(\\s+|)==(\\s+|)\".+?\"");
		Matcher matcher = pattern.matcher(str);
		indexes = str;
		while(matcher.find()) {
			String group = matcher.group();
			String[] arr = group.split("==");
			searchMap.put(arr[1].trim(), arr[0].trim());
			group = group.replaceAll("\".+?\"", "");
			indexes = indexes.replaceFirst(group, "");
		}
		
		pattern = Pattern.compile("in(\\s+|)\\([a-zA-Z_]{1,}.+?\\)");
		matcher = pattern.matcher(str);
		while(matcher.find()) {
			String in = matcher.group();
			String[] arr = in.replaceAll("^in\\(|\\)$", "").split(",");
			
			for(int i = 1; i < arr.length; i++){
				searchMap.put(arr[i].trim(), arr[0].replaceAll("in\\(|\\)","").trim());
			}
			String trans_in = CommonUtil.arrayToString(in.replaceAll("in(\\s+|)\\([a-zA-Z_]{1,},|\\)", "").split(",") , "", " or ");
			indexes = indexes.replace(in, "(" + trans_in + ")");
		}
		
		pattern = Pattern.compile("\".+?\"");
		matcher = pattern.matcher(str);
		while(matcher.find()) {
			String group = matcher.group();
			String tmp_group = group;
			if(group.split(delimiter).length > 0){
				String tmp_index = "";
				if(!ip_split && (searchMap.get(group).equals("s_info") || searchMap.get(group).equals("d_info") || searchMap.get(group).equals("terminal") || searchMap.get(group).equals("origin"))){
					tmp_index = tmp_group;
				}
				else {
					for(String shard : group.split(delimiter)){
						if(shard.length() > 0){
							tmp_index += "\"" + shard + "\" and ";
						}
					}
					tmp_index = tmp_index.replaceAll("\\sand\\s$", "");
					tmp_index = "(" + tmp_index + ")";
				}
				indexes = indexes.replace(tmp_group,  tmp_index );
			}
		}
		return indexes;
	}
	
}
