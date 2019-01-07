def main():
    # Please remember to change your database username and password as this is now Internet facing

    import MySQLdb
    import datetime

    mysqldb = MySQLdb.connect (host="172.16.100.129", port=3306, user="syslog", passwd="sys10g01!", db="Syslog")

    mysqldb_cursor = mysqldb.cursor()

    file = open("../RAW/test.log", "r")

    for line in file:
 