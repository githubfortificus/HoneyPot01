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
TCP_Ports = {}
UDP_Ports = {}
IP_Addresses = {}
ptr_cache = {}
DNS_cache = 0
DNS_resolved = 0

# Socket variables here
DNS_check = socket
DNS_check.setdefaulttimeout(1)

# Database connection here
# Please remember to change your database username and password as this is now Internet facing
mysqldb = MySQLdb.connect (host="172.16.122.129", port=3306, user="syslog", passwd="sys10g01!", db="Syslog")
mysqldb_cursor = mysqldb.cursor()

# Functions here
# This function creates a dictionary with Port - Count for TCP connections
def Port_function (F_Protocol, F_Port):
    global TCP_Ports
    global UDP_Ports

    if F_Protocol == "TCP":
        Counter = TCP_Ports.get(F_Port, 0)
        Counter += 1
        TCP_Ports.update({F_Port: Counter})
    # We asume UDP protocol here since the functions that send us here already checked for it
    else:
        Counter = UDP_Ports.get(F_Port, 0)
        Counter += 1
        UDP_Ports.update({F_Port: Counter})

# This function Counts the number of occurrences per IP
def IP_Add_function (F_IP):
    global IP_Addresses
    Counter = IP_Addresses.get(F_IP, 0)
    Counter += 1
    IP_Addresses.update({F_IP: Counter})

# This function obtains the domain / owner for the IP address
def Obtain_Domain (F_IP):       
    # Adding global variable definitions so that they can be modified in the function   
    global DNS_cache
    global DNS_resolved

    # Cache of identified addresses to optimize DNS resolution
    if ptr_cache.has_key(F_IP):
        DNS_cache += 1
        return ptr_cache[F_IP]

    # Here we check for Internal IP addresses so that we can prevent resolution
    IP = F_IP.split('.')
    if IP[0] == "172" or IP[0] == "192" or IP[0] == "10" or IP[0] == "169":
        ptr_cache[F_IP] = "Internal Network"
        return "Internal Network"        

    # Here we use the socket module with one second timeout to resolve the hostnames
    try:
        address = DNS_check.gethostbyaddr(F_IP)
        hostname = address[0]
        ptr_cache[F_IP] = hostname
        DNS_resolved += 1
        return hostname
    except:
        ptr_cache[F_IP] = "Unavailable"
        return "Unavailable"

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
    # FROM_DOMAIN = Obtain_Domain(SOURCEIP)
    FROM_DOMAIN = ""
    TO_DOMAIN = ""
    GeoIP = ""
    Priority = "0"
    Notes = ""

    Port_function(PROTOCOL, DESTINATIONPORT)
    IP_Add_function(SOURCEIP)

    mysqldb_cursor.execute('insert into January (Date, Time, Action, Protocol, SRCIP, SRCP, DSTIP, DSTP, Flags, ICMPTYPE, ICMPCODE, FROM_DOMAIN, Full_message) \
        values ("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%d", "%d", "%s", "%s")' % \
        (DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line))
        
    # print DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line

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
    # FROM_DOMAIN = Obtain_Domain(SOURCEIP)
    FROM_DOMAIN = ""
    TO_DOMAIN = ""
    GeoIP = ""
    Priority = "0"
    Notes = ""

    Port_function(PROTOCOL, DESTINATIONPORT)
    IP_Add_function(SOURCEIP)

    mysqldb_cursor.execute('insert into January (Date, Time, Action, Protocol, SRCIP, SRCP, DSTIP, DSTP, Flags, ICMPTYPE, ICMPCODE, FROM_DOMAIN, Full_message) \
        values ("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%d", "%d", "%s", "%s")' % \
        (DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line))

    # print DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line

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
    print Total_counter
    text = line.split()
    # # Processing for TCP connections here
    if ("TCP" in line) and not ("ICMP" in line):
        TCP_counter += 1
        # TCP - no DF
        if not "DF" in line:         
            DB_DF_not_present()
            # print PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT

        # TCP - DF
        else:
            DB_DF_present()        
            # print PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT
    else:
        # Processing for UDP connections here
        if ("UDP" in line) and not ("ICMP" in line):    
            UDP_counter += 1
            # UDP - No DF
            if not "DF" in line:
                DB_DF_not_present()
                # print PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT
                
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
                # FROM_DOMAIN = Obtain_Domain(SOURCEIP)
                FROM_DOMAIN = ""
                FLAGS = text[22:]
                FLAGS_INS = " ".join(FLAGS)

                # print DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line
                
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
Summary.write("DNS resolved %s\r\n" % DNS_resolved)
Summary.write("DNS cached %s\r\n" % DNS_cache)

# Here we sort the TCP and UDP dictionaries to see top 10 ports attacked and create the "daily" output
# print "\nTCP port analysis - Ports sorted from most access to least access"
for key, value in sorted(TCP_Ports.iteritems(), key=lambda (k,v): (v,k), reverse=True):
    print "%s: %s" % (key, value)

# print "\nUDP port analysis - Ports softed from most access to least access"
# for key, value in sorted(UDP_Ports.iteritems(), key=lambda (k,v): (v,k), reverse=True):
#     print "%s: %s" % (key, value)

# print "\nIP address analysis - IP addresses sorted from highest number of attacks"
# for key, value in sorted(IP_Addresses.iteritems(), key=lambda (k,v): (v,k), reverse=True):
#     print "%s: %s" % (key, value)
    
script_end = datetime.datetime.now()

print "Script start", script_start, "/ Script end", script_end

LOG.write("Finish file processing at %s\r\n" % script_end)
LOG.write("\r\n")

# Close files and database connections here
Input_file.close()
LOG.close()
Error.close()
Summary.close()
mysqldb_cursor.close()