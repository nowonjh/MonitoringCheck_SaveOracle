package com.igloosec;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.DecimalFormat;
import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;

import org.apache.log4j.Logger;

import com.igloosec.db.DBHandler;

/**
 * 
 * 외부 모듈들에 대한 추상클래스
 * 모든 모듈은 본 추상클래스를 상속받아 구현된다.
 * @author JH
 *
 */
public abstract class Module {
	protected final Logger logger;
	protected final String MODULE_NAME;
	protected final String DB_NAME;
	protected final int TIME_RANGE;
	
	private Calendar cal;
	private int currentSecond;
	private int millisec;
	private long delay;
	private Timer timer;
	private DecimalFormat df = new DecimalFormat("#.#");
	
	/**
	 * 생성자 - 모듈에 대한 정보를 받아 세팅되고
	 * 감사로그를 입력한다.
	 * @param logger_name
	 * @param db_name
	 * @param module_name
	 */
	protected Module(String logger_name, String db_name, String module_name, int time_range) {
		logger = LogManager.getInstance().getLogger(logger_name);
		this.MODULE_NAME = module_name;
		this.DB_NAME = db_name;
		this.TIME_RANGE = time_range;
		
		if(!audit_log("I", "V", this.MODULE_NAME + " started")) {
			System.exit(0);
			audit_log("E", "V", this.MODULE_NAME + " DB Connection refuse.");
		}
		init();
		timer = new Timer();
		timer.schedule(new Loop(), next_time(TIME_RANGE));
	}
	
	/**
	 * 감사로그 입력
	 * 생성객체를 확인하고 파라미터를 받아 감사로그를 생성한다.
	 * @param level
	 * @param subject
	 * @param note
	 * @return
	 */
	protected boolean audit_log(String level, String subject, String note) {
		String object = "";
		try {
			InetAddress addr = InetAddress.getLocalHost();
			object = System.getProperty("user.name") + "@" + addr.getHostAddress();
		} catch (UnknownHostException e) {
			logger.error(e.getMessage());
		} 
		String query = "insert into is_audit_log(lev, subject, object, note, idate) values ('" + level + "', '" + subject + "', '" + object + "', '" + note + "', sysdate)";
		boolean result = new DBHandler().excuteUpdate(DB_NAME, query);
		return result;
	}
	
	/**
	 * 외부모듈이 주기적으로 체크를하기때문에
	 * 다음에 수행되어야할 시간을 구한다.
	 * @param second
	 * @return
	 */
	protected long next_time(int second) {
		cal = Calendar.getInstance();
		currentSecond = cal.get(Calendar.SECOND);
		millisec = cal.get(Calendar.MILLISECOND);
		delay = (second - (currentSecond % 5)) * 1000 - millisec;
		
		return delay;
	}
	
	
	/**
	 * TimerTask 클래스를 상속받아
	 * Timer에 따라 실제 모듈이 해야하는 일을 수행시킴.
	 * @author JH
	 */
	protected class Loop extends TimerTask{
		@Override
		public void run() {
			try {
				excute();
			} catch (Exception e) {
				e.printStackTrace();
				logger.error(e.getMessage());
			} finally {
				if(timer == null){
					timer = new Timer();
				}
				else {
					timer.purge();
				}
				timer.schedule(new Loop(), next_time(TIME_RANGE));
			}
		}
	}
	
	/**
	 * 메모리 사용량에 로그에 기록한다.
	 */
	protected void printMemoryUsage() {
		double total = Runtime.getRuntime().totalMemory();
		double free = Runtime.getRuntime().freeMemory();
		double usage = total - free;
		logger.debug("Memory Usage : " + df.format(usage / 1024/1024) + "Mb / " + df.format(total /1024/1024) + "Mb  ( " + df.format(100 - free/total*100.0) + "% )");
	}
	
	/**
	 * 모듈이 수행해야하는 일을 구현한다. 
	 * @throws Exception
	 */
	protected abstract void excute() throws Exception;
	
	/**
	 * 모듈이 수행되기 위해 초기화 메소드
	 */
	protected abstract void init();
}
