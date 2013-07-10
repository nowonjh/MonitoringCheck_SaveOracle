#!/bin/sh

### COMMON CONFIG FILE READ ###
EXEC_FILE="$0"
BASE_NAME=`basename "$EXEC_FILE"`

if [ "$EXEC_FILE" = "./$BASE_NAME" ] || [ "$EXEC_FILE" = "$BASE_NAME" ]; then
	FULL_PATH=`pwd`
else
	FULL_PATH=`echo "$EXEC_FILE" | sed 's/'"${BASE_NAME}"'$//'`
	cd "$FULL_PATH"
	FULL_PATH=`pwd`
fi

source $FULL_PATH/../link.conf


### RDBMS SETTING ###
RDBMS_DRIVER=oracle.jdbc.driver.OracleDriver
RDBMS_CONNECTIONURL=jdbc:oracle:thin:@192.168.150.136:1521:ora10g
RDBMS_USERNAME=eas
RDBMS_PASSWORD=eas
RDBMS_OPTS=" -Drdbms.driver=$RDBMS_DRIVER -Drdbms.connectionurl=$RDBMS_CONNECTIONURL -Drdbms.username=$RDBMS_USERNAME -Drdbms.password=$RDBMS_PASSWORD"


### PRG SETTING ###
JAVA_HOME=$IS_HOME/java6
PRG_HOME=$IS_HOME/link/monitoringCheck
PRG_NAME=monitoringCheck.jar
PRG_ALIAS=monitoringCheckModule

### CLASSPATH ###

LOCALCLASSPATH=.:$PRG_HOME

####################################################
############    Default Setting    #################
####################################################

PRG_OPTS=" -Xms32m -Xmx64m -Dprg.home=$PRG_HOME -Djdbc.connectionurl=$JDBC_CONNECTIONURL -Djdbc.username=$JDBC_USERNAME -Djdbc.password=$JDBC_PASSWORD -Djdbc.driver=$JDBC_DRIVER -Dis.home=$IS_HOME"
PRG_PID=`ps -ef | grep -v grep | grep -v /bin/sh | grep "$PRG_ALIAS" | awk '{print $2 }'`

if [ ! -z "$PRG_PID" ]; then
	echo $PRG_ALIAS 'is already started!!!'
else
	$JAVA_HOME/bin/java -Dprg=$PRG_NAME -Dalias=$PRG_ALIAS $PRG_OPTS -jar $PRG_NAME >/dev/null 2>&1 &
	echo $PRG_ALIAS 'start!!!'
fi
