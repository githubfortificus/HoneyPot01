          # We already tested for TCP and UDP; testing for ICMP here
            if ("ICMP" in line):               
            # ICMP
                ICMP_counter += 1
                ICMP_counter += 1
                DATE = datetime.date(Year, Month, int(text[1]))
                HOUR = text[2]
                ACTION = text[7].replace(':','')
                SOURCEIP = text[11].replace('SRC=','')
                SOURCEPORT = 0
                DESTINATIONIP = text[12].replace('DST=','')
                DESTINATIONPORT = 0
                FROM_DOMAIN = ""

                # ICMP no DF section
                if ("ICMP" in line) and not ("DF" in line):
                    PROTOCOL = text[18].replace('PROTO=','')
                    ICMPTYPE = int(text[19].replace('TYPE=',''))
                    ICMPCODE = int(text[20].replace('CODE=',''))
                    FLAGS = text[21:]
                    FLAGS_INS = " ".join(FLAGS)

                    # print Source, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, ICMPTYPE, ICMPCODE, FLAGS_INS

                    mysqldb_cursor.execute('insert into Test (Source, Date, Time, Action, Protocol, SRCIP, SRCP, DSTIP, DSTP, Flags, ICMPTYPE, ICMPCODE, FROM_DOMAIN, Full_message) \
                        values ("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%d", "%d", "%s", "%s")' % \
                        (Source, DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line))
                
                    mysqldb.commit()

                    # ICMP with DF section
                    else:
                        

                            mysqldb_cursor.execute('insert into Test (Source, Date, Time, Action, Protocol, SRCIP, SRCP, DSTIP, DSTP, Flags, ICMPTYPE, ICMPCODE, FROM_DOMAIN, Full_message) \
                                values ("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%d", "%d", "%s", "%s")' % \
                                (Source, DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line))
                    
                            mysqldb.commit()

                        if ("TYPE=3" in line):
                            PROTOCOL = text[18].replace('PROTO=','')
                            ICMPTYPE = int(text[19].replace('TYPE=',''))
                            ICMPCODE = int(text[20].replace('CODE=',''))
                            FLAGS = text[21:]
                            FLAGS_INS = " ".join(FLAGS)
                            
                            # print Source, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, ICMPTYPE, ICMPCODE, FLAGS_INS
                            
                            mysqldb_cursor.execute('insert into Test (Source, Date, Time, Action, Protocol, SRCIP, SRCP, DSTIP, DSTP, Flags, ICMPTYPE, ICMPCODE, FROM_DOMAIN, Full_message) \
                                values ("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%s", "%d", "%d", "%s", "%s")' % \
                                (Source, DATE, HOUR, ACTION, PROTOCOL, SOURCEIP, SOURCEPORT, DESTINATIONIP, DESTINATIONPORT, FLAGS_INS, ICMPTYPE, ICMPCODE, FROM_DOMAIN, line))
                    
                            mysqldb.commit()
                    
                    # We enter this section if it is ICMP with DF but not type 8 or type 3
                    Other_counter += 1
                    Error.write("ICMP error on line: %s\r\n" % line)