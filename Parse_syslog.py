def main():

    import mysql.connector
    

    mysqldb = mysql.connector.connect (
        host="172.16.100.129",
        user="syslog",
        passwd="",
        database="Syslog"
    )
    
    mysqldb_handler = mysqldb.cursor()

    file = open("../RAW/data.log", "r")
    TCP_counter = 0
    UDP_counter = 0
    ICMP_counter = 0
    Other_counter = 0

    for line in file:
        text = line.split()
        sql_query = "insert into Syslog_December_2018 ('Date', \
                                                        'Time', \
                                                        'Action', \
                                                        'Protocol', \
                                                        'SRCIP', \
                                                        'SRCP', \
                                                        'DSTIP', \
                                                        'DSTP', \
                                                        'Flags', \
                                                        'ICMPTYPE', \
                                                        'ICMPCODE', \
                                                        'FROM_DOMAIN', \
                                                        'TO_DOMAIN', \
                                                        'GeoIP', \
                                                        'Priority', \
                                                        'Notes', \
                                                        'Full_message' ) \
                                                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        sql_values = ""
        if "TCP" in line:
            TCP_counter += 1
            if not "DF" in line:
                DATE = text[0] + " " + text[1]
                HOUR = text[2]
                ACTION = text[7].replace(':','')
                PROTOCOL = text[18].replace('PROTO=','')
                SOURCEIP = text[11].replace('SRC=','')
                SOURCEPORT = text[19].replace('SPT=','')
                DESTINATIONIP = text[12].replace('DST=','')
                DESTINATIONPORT = text[20].replace('DPT=','')
                FLAGS = text[23:]
                FLAGS_INS = " ".join(FLAGS)
                ICMPTYPE = ""
                ICMPCODE = ""
                FROM_DOMAIN = ""
                TO_DOMAIN = ""
                GeoIP = ""
                Priority = "0"
                Notes = ""
                test = ""
                #sql_values =    "(DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, \
                #                ICMPTYPE, ICMPCODE, FROM_DOMAIN, TO_DOMAIN, GeoIP, Priority, Notes, line)"
                mysqldb_handler.execute(sql_query, (DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS, \
                                ICMPTYPE, ICMPCODE, FROM_DOMAIN, TO_DOMAIN, GeoIP, Priority, Notes, test))
                # mysqldb_handler.execute(sql_query, sql_values)
                mysqldb_handler.commit()
                print DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS
            else:
                DATE = text[0] + " " + text[1]
                HOUR = text[2]
                ACTION = text[7].replace(':','')
                PROTOCOL = text[19].replace('PROTO=','')
                SOURCEIP = text[11].replace('SRC=','')
                SOURCEPORT = text[20].replace('SPT=','')
                DESTINATIONIP = text[12].replace('DST=','')
                DESTINATIONPORT = text[21].replace('DPT=','')
                FLAGS = text[24:]
                print DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS
        else:
            if "UDP" in line:    
                UDP_counter += 1
                if not "DF" in line:
                    DATE = text[0] + " " + text[1]
                    HOUR = text[2]
                    ACTION = text[7].replace(':','')
                    PROTOCOL = text[18].replace('PROTO=','')
                    SOURCEIP = text[11].replace('SRC=','')
                    SOURCEPORT = text[19].replace('SPT=','')
                    DESTINATIONIP = text[12].replace('DST=','')
                    DESTINATIONPORT = text[20].replace('DPT=','')
                    FLAGS = text[21:]
                    print DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS
                else:
                    DATE = text[0] + " " + text[1]
                    HOUR = text[2]
                    ACTION = text[7].replace(':','')
                    PROTOCOL = text[19].replace('PROTO=','')
                    SOURCEIP = text[11].replace('SRC=','')
                    SOURCEPORT = text[20].replace('SPT=','')
                    DESTINATIONIP = text[12].replace('DST=','')
                    DESTINATIONPORT = text[21].replace('DPT=','')
                    FLAGS = text[22:]
                    print DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS
            else:
                if "ICMP" in line:
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
                    print DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, ICMPTYPE, ICMPCODE, FLAGS
                else:
                    Other_counter += 1
                    print "No Protocol Found..."
    
    file.close()
    mysqldb.close()


    print "TCP Connections: ", TCP_counter
    print "UDP Connections: ", UDP_counter
    print "ICMP Connections: ", ICMP_counter
    print "OTHER Connections: ", Other_counter

main()