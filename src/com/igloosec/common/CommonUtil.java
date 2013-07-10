package com.igloosec.common;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import org.json.simple.JSONObject;

public class CommonUtil {
	
	public static int getTime(String str){
		//S,M,H,D
		int result = 0;
		
		if(str.equals("-") || str == null){
			return result;
		}
		
		String[] time = str.split("#");
		int num = Integer.parseInt(time[0]);
		if(time[1].equals("S")){
			result = num;
		}
		else if(time[1].equals("M")){
			result = num * 60;		
		}
		else if(time[1].equals("H")){
			result = num * 60 * 60;
		}
		else if(time[1].equals("D")){
			result = num * 60 * 60 * 24;
		}
		return result;
	}
	
	/**
	 * Real Ip를 구하는 함수
	 * @param ip
	 * @return
	 * @throws UnknownHostException
	 */
	public static long getRealIP(String ip)throws UnknownHostException {
		
		long realIP = InetAddress.getByName(ip.trim()).hashCode();
		
		if (realIP < 0) {
			return realIP ^ 0xFFFFFFFF00000000L;
		}
		return realIP;
	}
	
	/**
	 * 리스트를 String 으로 변환한다.
	 * @param table_list
	 * @param seperator
	 * @return
	 */
	public static String listToString(List<String> table_list, String cover, String seperator) {
		String result = "";
		for(Iterator<String> iter = table_list.iterator();iter.hasNext();){
			result += cover + iter.next().trim() + cover + seperator;
		}
		result = result.replaceAll("(\\s+|)" + seperator + "(\\s+|)$", "");
		return result;
	}
	
	public static String arrayToString(String[] array, String cover, String seperator) {
		String result = "";
		
		for(String one : array){
			result += cover + one.trim() + cover + seperator;
		}
		result = result.replaceAll("(\\s+|)" + seperator + "(\\s+|)$", "");
		return result;
	}
	
	
	public static JSONObject getResultFilter(Vector<Map<String, Object>> resultData, List<String> column_list) {
		int total_cnt = 0;
		List<Map<String, String>> list = new LinkedList<Map<String,String>>();
		for(Iterator<Map<String, Object>> iter = resultData.iterator(); iter.hasNext();){
			Map<String, Object> map = iter.next();
			
			Map<String, String> row_map = new LinkedHashMap<String, String>();
			for(int i = 0; i < column_list.size(); i++){
				String field = column_list.get(i).trim();
				row_map.put(field, map.get(field) + "");
			}
			list.add(row_map);
			total_cnt += Integer.parseInt(map.get("count") + "");	
		}
		
		JSONObject result = new JSONObject();
		result.put("filter", list);
		result.put("total_cnt", total_cnt + "");
		
		return result;
	}

	/**
	 * 해당되는 포트가 있는지 체크한다.
	 * @param es
	 * @param ip
	 * @param port
	 * @param timeout
	 * @return
	 */
	public static boolean portIsOpen(String ip, int port, int timeout) {
		Socket socket = new Socket();
		try {
			socket.connect(new InetSocketAddress(ip, port), timeout);
			socket.close();
			return true;
		} catch (IOException e) {
			return false;
		}
	}
}
