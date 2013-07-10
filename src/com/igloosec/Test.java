package com.igloosec;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Timer;
import java.util.TimerTask;
public class Test{

	
	Timer timer;
	Calendar cal;
	public Test(){
		timer = new Timer();
		timer.schedule(new Loop(), next_time(5));
	}
	
	/**
	 * 외부모듈이 주기적으로 체크를하기때문에
	 * 다음에 수행되어야할 시간을 구한다.
	 * @param second
	 * @return
	 */
	protected long next_time(int second) {
		cal = Calendar.getInstance();
		int currentSecond = cal.get(Calendar.SECOND);
		int millisec = cal.get(Calendar.MILLISECOND);
		int delay = (second - (currentSecond % 5)) * 1000 - millisec;
		
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
				if(timer == null){
					timer = new Timer();
				}
				else {
					timer.purge();
				}
				timer.schedule(new Loop(), next_time(5));
			} catch (Exception e) {
				e.printStackTrace();
				
			}
        }
	}
	
	public static void main(String[] args){
		new Test();
		
		
	}
	
	public void excute(){
		Thread t = new Thread(){
			public void run(){
				try {
					analysis();
				} catch (Exception e) {
				}
			}

			
		};
		t.start();
	}
	
	private void analysis() {
		Calendar scal = Calendar.getInstance();
		if(checkAnalysisTime(20, scal)){
			System.out.println(new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(scal.getTime()));
		}
		
	}
	
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
	
}
