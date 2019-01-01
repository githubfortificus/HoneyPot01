def main():
    file = open("../Apache/Dec.29.txt", "r")
    ATTACKS = 0
    
    for line in file:
        ATTACKS += 1
        text = line.split()
        # print text
        SOURCEIP = text[0]
        TIME = text[3].replace('[','')
        DATE = TIME.split(':')[0]
        HOUR = TIME.split(':')[1:]
        HOUR = ":".join(HOUR)
        METHOD = text[5].replace('"','')
        URL = text[6]
        TYPE = text[7].replace('"','')
        RESPONSE = text[8]
        SEP = line.split('"')
        CLIENT = SEP[5]
        print SOURCEIP, TIME, DATE, HOUR, METHOD, URL, TYPE, RESPONSE, CLIENT

    print "Number of attacks: ", ATTACKS
    
    file.close()

main ()