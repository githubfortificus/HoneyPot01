# This script will open a file created by SYSLOG in the honeypot and will parse the input, create a basic output 
# and push the data to a MySQL database for PHP processing.
#
# This script is to be run either by containers or serverless Cloud offerings (like AWS Lambda)
#
# V 0.1 
# Initial script, simple file parsing
#
# V 0.2
# Introduction to functions
#
# V 0.3
# Logging and basic file processing added
#
# V 0.4 
# Feeding data to MySQL database working
#
# V 0.5
# Removed all time consuming functions (like DNS and removed sorting to maximize Lambda performance)
# All of those old functions will be moved to a different script to be run from the RDS database in a container;
# please see script Parse_container.py for further information
#

# Needed modules here
import MySQLdb
import datetime
import socket
import sys

# Global variables here
Total_counter = 0
TCP_counter = 0
UDP_counter = 0
ICMP_counter = 0
Other_counter = 0

# Database connection here
# Please remember to change your database username and password as this is now Internet facing
mysqldb = MySQLdb.connect (host="172.16.122.129", port=3306, user="syslog", passwd="sys10g01!", db="Syslog")
mysqldb_cursor = mysqldb.cursor()

# Functions here
# This function updates the database for TCP/UDP with the DF flag present
def DB_DF_present ():
    DATE = datetime.date(Year, Month, int(text[1]))
    TIMESTR = text[2].replace(':',' ').split()
    HOUR = datetime.time(int(TIMESTR[0]), int(TIMESTR[1]), int(TIMESTR[2]))
    ACTION = text[7].replace(':','')
    PROTOCOL = text[19].replace('PROTO=','')
    SOURCEIP = text[11].replace('SRC=','')
    SOURCEPORT = text[20].replace('SPT=','')
    DESTINATIONIP = text[12].replace('DST=','')
    DESTINATIONPORT = text[21].replace('DPT=','')
    FLAGS = text[24:]
    FLAGS_INS = " ".join(FLAGS)
    ICMPTYPE = 0
    ICMPCODE = 0
    FROM_DOMAIN = ""
    TO_DOMAIN = ""
    GeoIP = ""
    Priority = "0"
    Notes = ""

    mysqldb_cursor.execute('insert into January (Date, Time, Action, Protocol, SRCIP, SRCP, DSTIP, DSTP, Flags, ICMPTYPE, ICMPCODE, FROM_DOMAIN, Full_message) \
        values ("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%d", "%d", "%s", "%s")' % \
        (DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line))
        
    mysqldb.commit()

# This function updates the database for TCP/UDP with the DF flag NOT present
def DB_DF_not_present ():
    DATE = datetime.date(Year, Month, int(text[1]))
    TIMESTR = text[2].replace(':',' ').split()
    HOUR = datetime.time(int(TIMESTR[0]), int(TIMESTR[1]), int(TIMESTR[2]))
    ACTION = text[7].replace(':','')
    PROTOCOL = text[18].replace('PROTO=','')
    SOURCEIP = text[11].replace('SRC=','')
    SOURCEPORT = text[19].replace('SPT=','')
    DESTINATIONIP = text[12].replace('DST=','')
    DESTINATIONPORT = text[20].replace('DPT=','')
    FLAGS = text[23:]
    FLAGS_INS = " ".join(FLAGS)
    ICMPTYPE = 0
    ICMPCODE = 0
    FROM_DOMAIN = ""
    TO_DOMAIN = ""
    GeoIP = ""
    Priority = "0"
    Notes = ""

    mysqldb_cursor.execute('insert into January (Date, Time, Action, Protocol, SRCIP, SRCP, DSTIP, DSTP, Flags, ICMPTYPE, ICMPCODE, FROM_DOMAIN, Full_message) \
        values ("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%d", "%d", "%s", "%s")' % \
        (DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line))

    mysqldb.commit()

# File Open here
# Here we test to see if a file argument is passed; otherwise, it will use the hard-coded value for data input
if len(sys.argv) < 2:
    Input_file = open("../RAW/data.log", "r")   
else:
    Input_file = open(sys.argv[1], "r")

# Here we open the log files
LOG = open("../Log/Parse_syslog.log", "a+")
Error = open("../Log/Parse_IPtables_error.log", "a+")
Summary = open("../Log/Parse_IPtables_Summary.log", "a+")

script_start = datetime.datetime.now()
Year = int(script_start.year)
Month = int(script_start.month)

# Main processing here
LOG.write("Starting file processing at %s\r\n" % script_start)

for line in Input_file:    
    Total_counter += 1
    text = line.split()
    # # Processing for TCP connections here
    if ("TCP" in line) and not ("ICMP" in line):
        TCP_counter += 1
        # TCP - no DF
        if not "DF" in line:         
            DB_DF_not_present()
        
        # TCP - DF
        else:
            DB_DF_present()        
    
    else:
        # Processing for UDP connections here
        if ("UDP" in line) and not ("ICMP" in line):    
            UDP_counter += 1
            # UDP - No DF
            if not "DF" in line:
                DB_DF_not_present()
                
            # UDP - DF
            else:
                DB_DF_present()
                # print PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT

        else:
            # ICMP
            if ("ICMP" in line) and not ("DF" in line):
                ICMP_counter += 1
                ICMP_counter += 1
                DATE = datetime.date(Year, Month, int(text[1]))
                HOUR = text[2]
                ACTION = text[7].replace(':','')
                PROTOCOL = text[18].replace('PROTO=','')
                SOURCEIP = text[11].replace('SRC=','')
                SOURCEPORT = 0
                DESTINATIONIP = text[12].replace('DST=','')
                DESTINATIONPORT = 0
                ICMPTYPE = int(text[19].replace('TYPE=',''))
                ICMPCODE = int(text[20].replace('CODE=',''))
                FROM_DOMAIN = ""
                FLAGS = text[22:]
                FLAGS_INS = " ".join(FLAGS)
                
                mysqldb_cursor.execute('insert into January (Date, Time, Action, Protocol, SRCIP, SRCP, DSTIP, DSTP, Flags, ICMPTYPE, ICMPCODE, FROM_DOMAIN, Full_message) \
                    values ("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%d", "%d", "%s", "%s")' % \
                    (DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line))

                mysqldb.commit()
            
            # Protocol not detected here
            else:
                Other_counter += 1
                Error.write("Error on line: %s\r\rn" % line)

Summary.write("\r\n\r\n")
Summary.write("Date: - - - \r\n")
Summary.write("Total number of Connections: %s\r\n" % Total_counter)
Summary.write("TCP Connections: %s\r\n" % TCP_counter)
Summary.write("UDP Connections: %s\r\n" % UDP_counter)
Summary.write("ICMP Connections: %s\r\n" % ICMP_counter)
Summary.write("OTHER Connections: %s\r\n" % Other_counter)
    
script_end = datetime.datetime.now()

LOG.write("Finish file processing at %s\r\n" % script_end)
LOG.write("\r\n")

# Close files and database connections here
Input_file.close()
LOG.close()
Error.close()
Summary.close()
mysqldb_cursor.close()