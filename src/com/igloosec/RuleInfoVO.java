package com.igloosec;

import org.json.simple.JSONObject;

public class RuleInfoVO {
	private int monitor_id;
	private int rule_id;
	private String category;
	private String title;
	private String description;
	private int cycle;
	private int range;
	private int delay;
	private JSONObject param;
	private JSONObject manager_agent;
	private String group_name;
	private String user_id;
	private String origin_type;
	private String correlation;
	private String exe_query;
	private String idate;
	
	
	public int getMonitor_id() {
		return monitor_id;
	}
	public void setMonitor_id(int monitor_id) {
		this.monitor_id = monitor_id;
	}
	public int getRule_id() {
		return rule_id;
	}
	public void setRule_id(int rule_id) {
		this.rule_id = rule_id;
	}
	public String getCategory() {
		return category;
	}
	public void setCategory(String category) {
		this.category = category;
	}
	public String getTitle() {
		return title;
	}
	public void setTitle(String title) {
		this.title = title;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public int getCycle() {
		return cycle;
	}
	public void setCycle(int cycle) {
		this.cycle = cycle;
	}
	public int getRange() {
		return range;
	}
	public void setRange(int range) {
		this.range = range;
	}
	public int getDelay() {
		return delay;
	}
	public void setDelay(int delay) {
		this.delay = delay;
	}
	public JSONObject getParam() {
		return param;
	}
	public void setParam(JSONObject param) {
		this.param = param;
	}
	public JSONObject getManager_agent() {
		return manager_agent;
	}
	public void setManager_agent(JSONObject manager_agent) {
		this.manager_agent = manager_agent;
	}
	public String getGroup_name() {
		return group_name;
	}
	public void setGroup_name(String group_name) {
		this.group_name = group_name;
	}
	public String getUser_id() {
		return user_id;
	}
	public void setUser_id(String user_id) {
		this.user_id = user_id;
	}
	public String getOrigin_type() {
		return origin_type;
	}
	public void setOrigin_type(String origin_type) {
		this.origin_type = origin_type;
	}
	public String getCorrelation() {
		return correlation;
	}
	public void setCorrelation(String correlation) {
		this.correlation = correlation;
	}
	public String getExe_query() {
		return exe_query;
	}
	public void setExe_query(String exe_query) {
		this.exe_query = exe_query;
	}
	public String getIdate() {
		return idate;
	}
	public void setIdate(String idate) {
		this.idate = idate;
	}
	
}
