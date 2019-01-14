def main():
    # Please remember to change your database username and password as this is now Internet facing

    # Modules here
    import MySQLdb
    import datetime

    # Global variables here
    Total_counter = 0
    TCP_counter = 0
    UDP_counter = 0
    ICMP_counter = 0
    Other_counter = 0
    TCP_Ports = {}
    UDP_Ports = {}

    # Database connection here
    # mysqldb = MySQLdb.connect (host="172.16.100.129", port=3306, user="syslog", passwd="sys10g01!", db="Syslog")
    # mysqldb_cursor = mysqldb.cursor()

    # Functions here
    def Port_function (F_Protocol, F_Port):
        Counter = TCP_Ports.get(F_Port, 0)
        Counter += 1
        # print "The counter for port - is: ", F_Port, Counter
        TCP_Ports.update({F_Port: Counter})
        print TCP_Ports[F_Port]
        # print "The value for TCP_Ports[F_Port] is: ", TCP_Ports[F_Port]
        print "The information passed is: ", F_Protocol, F_Port

    def DB_DF_present ():
        print "We would insert to the database this information: ", PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT

    def DB_DF_not_present ():
        print "We would insert to the database this information: ", PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT

    # File Open here
    Input_file = open("../RAW/data.log", "r")   
    Syslog_processed = open("../Apache_Processed/syslog.out", "a+") 
    Apache_Processed = open("../Syslog_Processed/apache.out", "a+")  
    LOG = open("../Log/Parse_syslog.log", "a+")
    Error = open("../Log/Parse_IPtables_error.log", "a+")
    Summary = open("../Log/Parse_IPtables_Summary.log", "a+")

    # Main processing here
    for line in Input_file:
        Total_counter += 1
        text = line.split()
        # Processing for TCP connections here
        if "TCP" in line:
            TCP_counter += 1
            # TCP - no DF
            if not "DF" in line:
                DATE = datetime.date(2018, 12, int(text[1]))
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

                Port_function (PROTOCOL, DESTINATIONPORT)

                print PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT

            # TCP - DF
            else:
                DATE = datetime.date(2018, 12, int(text[1]))
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
        
                print PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT
        else:
            # Processing for UDP connections here
            if "UDP" in line:    
                UDP_counter += 1
                # UDP - No DF
                if not "DF" in line:
                    DATE = datetime.date(2018, 12, int(text[1]))
                    TIMESTR = text[2].replace(':',' ').split()
                    HOUR = datetime.time(int(TIMESTR[0]), int(TIMESTR[1]), int(TIMESTR[2]))
                    ACTION = text[7].replace(':','')
                    PROTOCOL = text[18].replace('PROTO=','')
                    SOURCEIP = text[11].replace('SRC=','')
                    SOURCEPORT = text[19].replace('SPT=','')
                    DESTINATIONIP = text[12].replace('DST=','')
                    DESTINATIONPORT = text[20].replace('DPT=','')
                    FLAGS = text[21:]
                    FLAGS_INS = " ".join(FLAGS)

                    print PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT
                    
                # UDP - DF
                else:
                    DATE = datetime.date(2018, 12, int(text[1]))
                    TIMESTR = text[2].replace(':',' ').split()
                    HOUR = datetime.time(int(TIMESTR[0]), int(TIMESTR[1]), int(TIMESTR[2]))
                    ACTION = text[7].replace(':','')
                    PROTOCOL = text[19].replace('PROTO=','')
                    SOURCEIP = text[11].replace('SRC=','')
                    SOURCEPORT = text[20].replace('SPT=','')
                    DESTINATIONIP = text[12].replace('DST=','')
                    DESTINATIONPORT = text[21].replace('DPT=','')
                    FLAGS = text[22:]
                    FLAGS_INS = " ".join(FLAGS)

                    print PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT

            else:
                # ICMP
                if "ICMP" in line:
                    ICMP_counter += 1
                    ICMP_counter += 1
                    DATE = text[0] + " " + text[1]
                    HOUR = text[2]
                    ACTION = text[7].replace(':','')
                    PROTOCOL = text[18].replace('PROTO=','')
                    SOURCEIP = text[11].replace('SRC=','')
                    SOURCEPORT = 0
                    DESTINATIONIP = text[12].replace('DST=','')
                    DESTINATIONPORT = 0
                    ICMPTYPE = text[19].replace('TYPE=','') 
                    ICMPCODE = text[20].replace('CODE=','')
                    FLAGS = text[22:]
                    FLAGS_INS = " ".join(FLAGS)

                    print PROTOCOL, SOURCEIP,  DESTINATIONIP, ICMPTYPE, ICMPCODE
                
                # Protocol not detected here
                else:
                    Other_counter += 1

                    print "No protocol detected...  Problem found"

    print "Total number of Connections: ", Total_counter
    print "TCP Connections: ", TCP_counter
    print "UDP Connections: ", UDP_counter
    print "ICMP Connections: ", ICMP_counter
    print "OTHER Connections: ", Other_counter

    # Close files and database connections here
    Input_file.close()
    LOG.close()
    Syslog_processed.close()
    Apache_Processed.close()
    Error.close()
    Summary.close()
    # mysqldb_cursor.close()

main()