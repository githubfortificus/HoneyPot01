#/bin/bash

# Environment variables here
HOME=/Data/Syslog
RAW=$HOME/RAW
DATABASE_INPUT=$HOME/DB
LOG=$HOME/Log/copy_logs.log
APACHE=$HOME/Apache
INBOUND=$HOME/Inbound
OUTBOUND=$HOME/Outbound
BIN=$HOME/Code

NOW=`/bin/date`

echo "Starting processing at: $NOW ... " >> $LOG

# Time variables here
# Notice the multiple options due to month change / year change.
# Using the date string would be more elegant; left as a task to be done as time allows.
Month=`/bin/date -d "18 hours ago" +%b`
Previous_Month=`/bin/date -d "42 hours ago" +%b`
Day=`date -d "18 hours ago" +%_d`
Previous_Day=`date -d "42 hours ago" +%_d`
File_Day=`echo $Day | sed 's/ //g'`

# File Strings
# The SED is because of date string manipulation (again).
# Cleanup to be done as time allows.
FW_Yesterday=`echo "$Month.$Day.txt" | sed 's/ //g'`
FW_Previous=`echo "$Previous_Month.$Previous_Day.txt" | sed 's/ //g'`
Apache_FN=`echo "$Month.$Day.txt" | sed 's/ //g'`

# Temporary troubleshooting here
# cat $RAW/$FW_Previous $RAW/$FW_Yesterday | grep "$Month $Day" | grep Outbound >> $OUTBOUND/$Month.$File_Day.OUT.log
# cat $RAW/$FW_Previous $RAW/$FW_Yesterday | grep "$Month $Day" | grep Inbound >> $INBOUND/$Month.$File_Day.IN.log

# Main processing here...
# Copy files for backup
echo "Starting file copy to $RAW/$FW_Yesterday and $APACHE/$Apache_FN" >> $LOG
        cp /var/log/syslog.1 $RAW/$FW_Yesterday
        cp /var/log/apache2/access.log.1 $APACHE/$Apache_FN
echo "Copy finished ..." >> $LOG

# Creation of Database input file here
echo "Creating Database input file here... " >> $LOG 
        cat $RAW/$FW_Previous $RAW/$FW_Yesterday | egrep "Inbound|Outbound" >> $DATABASE_INPUT/$Month.$File_Day.log

# Create Inbound and Outbound files
echo "Creating Syslog Daily log files (Inbound and Outbound)..." >> $LOG
        cat $RAW/$FW_Previous $RAW/$FW_Yesterday | grep "$Month $Day" | grep Inbound >> $INBOUND/$Month.$File_Day.IN.log
        cat $RAW/$FW_Previous $RAW/$FW_Yesterday | grep "$Month $Day" | grep Outbound >> $OUTBOUND/$Month.$File_Day.OUT.log

# Feed Syslog data to the database here
echo "Executing python script to send data to the database..." >> $LOG
python $BIN/Parse_Syslog_0.1.py $DATABASE_INPUT/$Month.$File_Day.log AWSHoney01

# Data to the Apache database here


# Compressing old files here
echo "Compressing $RAW/$FW_Yesterday and $DATABASE_INPUT/$Month.$File_Day.log" >> $LOG       
        gzip $RAW/$FW_Yesterday
        gzip $DATABASE_INPUT/$Month.$File_Day.log
