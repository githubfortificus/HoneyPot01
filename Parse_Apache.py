#
#
#

# Needed modules here
import MySQLdb
import sys
import datetime

from time import strptime

# Global variables here
IP_Addresses = {}
ptr_cache = {}
DNS_cache = 0
DNS_resolved = 0
ATTACKS = 0

# Database connection here
# Please remember to change your database username and password as this is now Internet facing
mysqldb = MySQLdb.connect (host="172.16.122.129", port=3306, user="syslog", passwd="sys10g01!", db="Syslog")
mysqldb_cursor = mysqldb.cursor()

# Functions here
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

# File Open here
# Here we test to see if a file argument is passed; otherwise, it will use the hard-coded value for data input
if len(sys.argv) < 2:
    file = open("../RAW/Jan.12.txt", "r")   
else:
    file = open(sys.argv[1], "r")

LOG = open("../Log/Parse_Apache.log", "a+")

# Main processing here
for line in file:
    ATTACKS += 1
    # print ATTACKS
    text = line.split()
    # print text
    SOURCEIP = text[0]
    DOMAIN = Obtain_Domain(SOURCEIP)
    TIME = text[3].replace('[','')
    DATE = TIME.split(':')[0]
    DATE = DATE.split('/')
    MONTH = strptime(DATE[1], '%b').tm_mon
    DATE = datetime.date(int(DATE[2]), MONTH, int(DATE[0]))
    HOUR = TIME.split(':')[1:]
    HOUR = datetime.time(int(HOUR[0]), int(HOUR[1]), int(HOUR[2]))
    METHOD = text[5].replace('"','')
    URL = text[6]
    TYPE = text[7].replace('"','')
    try:
        RESPONSE = int(text[8])
    except:
        RESPONSE = 0
    SEP = line.split('"')
    CLIENT = SEP[5]

    # We insert the values into the databaser here.
    mysqldb_cursor.execute('insert into January_Apache (SOURCEIP, DOMAIN, TIME, DATE, METHOD, URL, TYPE, RESPONSE, CLIENT) \
        values ("%s", "%s", "%s", "%s", "%s", "%s", "%s", "%d", "%s")' % \
        (SOURCEIP, DOMAIN, HOUR, DATE, METHOD, URL, TYPE, RESPONSE, CLIENT))

    mysqldb.commit()

mysqldb_cursor.close()

file.close()
LOG.close()