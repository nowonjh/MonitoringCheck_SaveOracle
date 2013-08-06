package com.igloosec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.araqne.logdb.client.IndexInfo;
import org.araqne.logdb.client.LogDbClient;
import org.araqne.logdb.client.TableInfo;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;

import com.igloosec.common.CommonUtil;
import com.igloosec.db.DBConnectionManager;
import com.igloosec.db.DBHandler;

/**
 * 
 * @author JH
 *
 */
public class CacheManager {
	static Logger logger = LogManager.getInstance().getLogger("monitoringCheck.log");
	
	private static CacheManager instance;
	private Properties config;
	private long configModified;
	private File configFile;
	
	private Map<String, TableInfo> tableMap;
	private Map<String, IndexInfo> indexMap;
	
	private Map<String, RuleInfoVO> rule_list;
	
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
			logger.info("extrim.properties file read...");
			configModified = configFile.lastModified();
			
			try {
				config.load(new FileInputStream(configFile));
			} catch (FileNotFoundException e) {
				logger.error(configFile.getAbsolutePath() + " not found..", e);
			} catch (IOException e) {
				logger.error(e.getMessage(), e);
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
	
	
	/**
	 * Araqne Table 및 index 정보를 갱신한다.
	 */
	public void initTableList(String dbname) {
		tableMap = Collections.synchronizedMap(new LinkedHashMap<String, TableInfo>());
		indexMap = Collections.synchronizedMap(new LinkedHashMap<String, IndexInfo>());
		
		String query = "select mgr_ip from agent_info_list group by mgr_ip";
		String[] mgr_list = new DBHandler().getOneColumnData(dbname, query);

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
				logger.error(e.getMessage(), e);
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
	 * 모니터링 룰 리스트를 전역Map에 보관한다.
	 */
	public void initRuleList(String dbname) {
		String query = "SELECT a.id, a.rule_id, a.category, a.origin_type, a.title, a.description, a.CYCLE, a.RANGE, " +
				"a.DELAY, a.param, a.agent_list, a.group_name, a.user_id, a.correlation, b.exe_query, a.idate " +
				"FROM is_user_defined_monitor a JOIN is_user_defined_rule b ON a.rule_id = b.id";
		String[][] data = new DBHandler().getNColumnData(dbname, query);
		
		rule_list = Collections.synchronizedMap(new LinkedHashMap<String, RuleInfoVO>());
		for(String[] row : data){
			
			RuleInfoVO rule = new RuleInfoVO();
			rule.setMonitor_id(Integer.parseInt(row[0]));
			rule.setRule_id(Integer.parseInt(row[1]));
			rule.setCategory(row[2]);
			rule.setOrigin_type(row[3]);
			rule.setTitle(row[4]);
			rule.setDescription(row[5]);
			rule.setCycle(CommonUtil.getTime(row[6]));
			rule.setRange(CommonUtil.getTime(row[7]));
			rule.setDelay(CommonUtil.getTime(row[8]));
			rule.setParam((JSONObject) JSONValue.parse(row[9]));
			rule.setManager_agent((JSONObject) JSONValue.parse(row[10]));
			rule.setGroup_name(row[11]);
			rule.setUser_id(row[12]);
			rule.setCorrelation(row[13]);
			rule.setExe_query(row[14].replaceAll("\t|\n", " ").replaceAll("\\s+", " "));
			rule.setIdate(row[15]);
			
			rule_list.put(row[0], rule);
		}
	}

	public Map<String, TableInfo> getTableMap() {
		return tableMap;
	}

	public Map<String, IndexInfo> getIndexMap() {
		return indexMap;
	}

	public Map<String, RuleInfoVO> getRule_list() {
		return rule_list;
	}	
}
