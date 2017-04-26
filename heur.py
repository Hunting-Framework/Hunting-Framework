# Libraries to import 
import csv
import requests
import json
import urllib.request
import re
import time
import datetime
import os
import sys
from requests.exceptions import ConnectionError

# This script conducts analysis and heuristics based on the csv files created by the previous script.
# The csv files are read in, and data is processed in the extract class mainly into lists for heuristic analysis.
# In the heuristics class, the functions return a list built up of lists and data, such as IPs or domains flagged along with a score etc.


#Make sure that the file is the right one
#Check there is an internet connection...

#Finish Alexa by splitting the return value as per VT


# Most of the functions in this class follow the pattern of:
# - Check whether they have been called correctly
# - Open the relevant csv file and extract all data into a list
# - Clean the list and make it unique
# - Return the clean list for analysis by later functions
class extract:
    files = []
    # Read in Files from tempfile which are cleaned using str manipulation 
    # each line of tempfile read in with for loop
    with open('Output/tempfile.temp', 'rb') as tempfile:
        for csvfile in tempfile:
            csvfile = str(csvfile)
            csvfile = csvfile.split(sep="b'")
            csvfile = csvfile[1]
            csvfile = csvfile.split(sep="\\n'")
            csvfile = csvfile[0]
            csvfile = csvfile.split(sep="'")
            csvfile = csvfile[0]
            csvfile = csvfile.split(sep="\\r")
            csvfile = csvfile[0]
            # After the line in tempfile has been cleaned add them to a list containing filenames of csv files, hash
            # nameservers and filename
            files.append(csvfile)

    def Gen4(self):
        tag = 0
        filelist = self.files
        #Initialise File1 Variable
        file1 = ""
        # Going through the list of files created above to search for one with "IPv4 in the filename"
        # This section is a check as this function isn't called unless the code at the bottom of the script
        # detects IPv4
        for file in filelist:
            if "IPv4" in file:
                file1 = file
                tag = 1
                print("IPv4 file detected for input...")
        if(tag == 0):
            print("No IPv4 File Detected For Input...")
        file1 = "Output/" + file1
        iplist = []
        # Open the IPv4 csv and read in all of the IP addresses to a list
        with open (file1,'r') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            for row in reader:
                iplist.append(row[0])
                iplist.append(row[1])
        #Use set to unique the IPs
        unique = list(set(iplist))
        #print(len(unique))
        #print(unique)

        # Remove Local IP addresses
        noreserved = []
        #initialise token
        # The below loop looks to remove local IP addresses from the list of extracted IPs
        for ip in unique:
            token = 0
            if(ip == ""):
                token = 1
            tempsplit = ip.split(sep=".")
            if(tempsplit[0] == "127"):
                token = 1
            if(tempsplit[0] == "10"):
                token = 1
            if(tempsplit[0] == "192" and tempsplit[1] == "168"):
                token = 1
            if(tempsplit[0] == "172" and (int(tempsplit[1]) >= 16 and int(tempsplit[1]) <= 31)):
                token = 1
            if(ip != ""):
                int1 = int(tempsplit[0])
                int2 = int(tempsplit[1])
                if(int1 >= 224 and int2 <= 239):
                    token = 1
            # Apple IP Netblock and Other known good IP addresses
            # If none of the above if statements are triggered by a local address then add to the no local list.
            if(token == 0):
                noreserved.append(ip)
        print("IPv4 File Processed...")
        return(noreserved)
########################################################################################  
# This function extracts processes the IPv6 csv and creates a list of IPv6 addresses, this function returns a list of IPv6 addresses. 
    def Gen6(self):
        tag = 0
        filelist = self.files
        #Initialise File1 Variable
        file1 = ""
        for file in filelist:
            if "IPv6" in file:
                file1 = file
                tag = 1
                print("IPv6 file detected for input...")
        if(tag == 0):
            print("No IPv6 File Detected For Input...")
        file1 = "Output/" + file1
        iplist = []
        # Open IPv6 csv and extract the IPs to a list
        with open (file1,'r') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            for row in reader:
                iplist.append(row[0])
                iplist.append(row[1])
        #Use set to unique the IP
        unique = list(set(iplist))
        #print(len(unique))
        #print(unique)
        noreserved6 = []
        # Check for local / redundant IPv6 addresses
        for ip6 in unique:
            token = 0
            if(ip6 == ""):
                token = 1
            if(ip6 == "::1"):
                token = 1
            if(ip6 == "::"):
                token = 1
            tempsplit = ip6.split(sep=":")
            if(token == 0):
                noreserved6.append(ip6)
        print("IPv6 File Processed...")
        return(noreserved6)
####################################################
# This function returns a list of unique domains.
    def DNS(self):
        tag = 0
        filelist = self.files
        #Initialise File1 Variable
        file1 = ""
        # Check DNS is in the filename
        for file in filelist:
            if "DNS" in file:
                file1 = file
                tag = 1
                print("DNS file detected for input...")
        if(tag == 0):
            print("No DNS File Detected For Input...")
        file1 = "Output/" + file1
        domainlist = []
        # Open DNS csv and extract all domains
        with open (file1,'r') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            for row in reader:
                domainlist.append(row[0])
        domainlistclean = []
        uniquedomains = list(set(domainlist))
        uniquedomainsdot = []
        #print(uniquedomains)
        for local in uniquedomains:
            if(local == ""):
                uniquedomains.remove(local)
                break
        for local in uniquedomains:
            if '.' in local:
                uniquedomainsdot.append(local)
        # Remove some 'domains' which are extracted by tshark.
        for local in uniquedomainsdot:
            if(local == "_airport._tcp.local"):
                uniquedomainsdot.remove(local)
            if(local == "_raop._tcp.local"):
                uniquedomainsdot.remove(local)
            if(local == "wpad.localdomain"):
                uniquedomainsdot.remove(local)
# Any domains or subdomains of the following list are whitelisted and removed from proceeding any further.
        whitelist = ['_tcp.local','in-addr.arpa','google.com','google.co.uk','bbc.co.uk','youtube.com','facebook.com','amazon.com','yahoo.com','twitter.com','linkedin.com','instagram.com','bing.com','outlook.com']

        # The below checks for subdomains of the above and then removes them.
        for clean in whitelist:
            for domain in uniquedomainsdot:
                clean1 = clean.split(sep=".")
                domain1 = domain.split(".")
                if(len(clean1) > 2):
                    if(clean1[-1] == domain1[-1] and clean1[-2] == domain1[-2] and clean1[-3] == domain1[-3]):
                        uniquedomainsdot.remove(domain)     
                else:
                    if(len(clean1) <= 2):
                        if(clean1[-1] == domain1[-1]):
                            if(clean1[-2] == domain1[-2]):
                                uniquedomainsdot.remove(domain)
        print("DNS File Processed...")       
        return(uniquedomainsdot)

####################################################
# This function returns a list of IP addresses acquired via DNS responses.
    def DNS2(self):
        tag = 0
        filelist = self.files
        #Initialise File1 Variable
        file1 = ""
        for file in filelist:
            if "SND" in file:
                file1 = file
                tag = 1
                print("DNS2 file detected for input...")
        if(tag == 0):
            print("No DNS2 File Detected For Input...")
        file1 = "Output/" + file1
        dnsip = []
        # Extract all IP addresses returned via DNS for the csv and insert into list
        with open (file1,'r') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            for row in reader:
                dnsip.append(row)
        dnsipremoveblank = []
        # Removes blanks from list
        for row2 in dnsip:
            if row2:
                for ip in row2:
                    dnsipremoveblank.append(ip)
        dnsipremoveblank = set(dnsipremoveblank)
        print("DNS2 File Processed...")
        return(dnsipremoveblank)    

####################################################
# This function creates a list of IP addresses which DNS requests have been made to
    def DNS3(self):
        tag = 0
        filelist = self.files
        #Initialise File1 Variable
        file1 = ""
        for file in filelist:
            if "DNIPS" in file:
                file1 = file
                tag = 1
                print("DNS3 file detected for input...")
        if(tag == 0):
            print("No DNS3 File Detected For Input...")
        file1 = "Output/" + file1
        dnsips = []
        requestips = []
        with open (file1,'r') as csvfile:
             reader = csv.reader(csvfile, delimiter=',')
             for row in reader:
                 if(row[0] == '0'): # row begins with 0 if it is a DNS query (see Main.py/Tshark filters)
                     dnsips.append(row)
        for list1 in dnsips:
            templist = []
            for element in list1:
                if(element != ""):
                    templist.append(element)    
            requestips.append(templist[-1])
        requestips = set(requestips)
        return(requestips)
####################################################
    def Port(self):
        tag = 0
        filelist = self.files
        #Initialise File1 Variable
        file1 = ""
        for file in filelist:
            if "Port" in file:
                file1 = file
                tag = 1
                print("Port file detected for input...")
        if(tag == 0):
            print("No Port File Detected For Input...")
        file1 = "Output/" + file1
        ports = []
        # extract and create a list of corresponding ports
        with open (file1,'r') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            for row in reader:
                portlisttemp = []
                for field in row:
                    if(field != ""):
                        portlisttemp.append(field)
                if(len(portlisttemp) != 0):
                    ports.append(portlisttemp)
        print("Port File Processed...")
        return(ports)      
                
####################################################
    def TLS(self):
        tag = 0
        filelist = self.files
        #Initialise File1 Variable
        file1 = ""
        for file in filelist:
            if "TLS" in file:
                file1 = file
                tag = 1
                print("TLS file detected for input...")
        if(tag == 0):
            print("No TLS File Detected For Input...")
            
            
        file1 = "Output/" + file1
        tlsversion = []
        ciphers = []
        # Open csv file and extract the TLS version value
        with open (file1,'r') as csvfile:
            reader = csv.reader(csvfile, delimiter=',')
            for row in reader:
                tlsversion.append(row[0])
                ciphers.append(row) # List of cipher suites, requires processing (not used for heuristics yet)
        tlsversionnoblank = []
        for version in tlsversion:
            if(version != ""):
                tlsversionnoblank.append(version)
        print("TLS File Processed...")
        return(tlsversionnoblank)
        
####################################################

# Returns a list of the files for usage outside the class
    def functionstocall(self):
        filelist = self.files
        return(filelist)
                

################### Heuristics Class #################################
# This class contains the heuristics and most of the functions take input in the form of
# lists processed by the above class. The functions tend to return a list containing lists and values
# these are then manipulated and processed below this class.
class heuristics:
    score = 0
    iocs = []

    # This class seeks to find domains which resemble those produced by a DGA
    def DGA(self,domains):
        score1 = self.score
        longlist = []
        dgalist = []
        for domain in domains:
            domainsplit = list(domain)
            if(len(domainsplit) > 20):
                longlist.append(domain)
                score1 = score1 + 5

        # Given a list of domains over 20 chars in length
        for domain in longlist:
            domainsplit = list(domain)
            lengthofdomain = len(domainsplit)
            pairs = lengthofdomain - 1
            counter = 0
            normal = []
            vowels = ['a','e', 'i', 'o', 'u']
            consonants = ['b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'x', 'z','y','w']
            matchcount = 0
            # The code compares neighbour characters to see if they are vowel/consonant opposites - if there is a small amount of these opposites
            # then the word is likey to be illegible and computer generated. Implement Markov chains as an alternative.
            for character in domainsplit:
                if(counter == 0):
                    prev = ''
                if character in consonants:
                    if prev in vowels:
                        matchcount = matchcount + 1
                else:
                    if character in vowels:
                        if prev in consonants:
                            matchcount = matchcount + 1  
                prev = character
                counter = counter + 1
            percentage = ((matchcount / pairs)* 100)
            if(percentage < 25):
                dgalist.append(domain)
                score1 = score1 + 20
        returnlist = []
        returnlist.append(dgalist)
        returnlist.append(longlist)
        returnlist.append(score1)
        return(returnlist)

    # This function queries the Virustotal API with the list of indicators - domains/IPs - which it is given.
    def VirusTotal(self,querylist,mode):
        #print(querylist)
        #querylist = []
        totallen = len(querylist)
        print("Mode: " + mode)
        print("Number of queries to make: " + str(totallen))
        score1 = self.score
        iocs1 = self.iocs
        positivescanners = []
        errorlist = []
        naughtylist = []
        counter = 1
        # Atempt the below to check if there is an Internet Connection
        try:
            r = requests.get("http://data.alexa.com/data?cli=10&dat=s&url=www.google.com", timeout=1)
        except ConnectionError as e:
            print("No Internet Connection, Skipping VirusTotal Function...")
            return False
        for indicator in querylist:
        # 4 Requests Per minute
        # VT Sample Code from their website https://www.virustotal.com/en/documentation/public-api/
            headers = {
              "Accept-Encoding": "gzip, deflate",
              "User-Agent" : "gzip,  My Python requests library example client or username"
              }
            params = {'apikey': '', 'resource':indicator} # INSERT VIRUSTOTAL KEY ON THIS LINE in the ''
            response = requests.post('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
            #json_response = response.json()
            try:
                json_response = json.loads(response.text)
            # If the above fails append indicator to an errorlist
            except (ValueError, ConnectionError):
                print("Value Error or Connection Error Occured")
                errorlist.append(indicator)
                time.sleep(17)
                counter = counter + 1
                continue
            # VT query has succeeded    
            print("VirusTotal Query Sent Waiting For Query Timer to Reset...")
            remaining = int(totallen) - int(counter)
            print(str(remaining) + " " + mode + " remaining")
            counter = counter + 1
            queried = json_response['resource']
            # Manipulate JSON response to check if it returned 0 or some positive hits
            if(json_response['response_code'] == 0):
                print("Resource " + str(queried) + " gave a response code of 0")
                errorlist.append(indicator)
                if(remaining == 0):
                    continue
                time.sleep(17) 
                continue
            result = json_response['positives']
            result = int(result)
            scans = json_response['scans']
            
            # Assign a score dependant on the number of positives returned
            if(result != 0):
                if(result > 0 and result < 10):
                    score1 = score1 + 50
                    naughtylist.append(indicator)
                    print("VirusTotal Hit! - " + indicator)
                if(result > 10):
                    score1 = score1 + 100
                    naughtylist.append(indicator)
                    print("VirusTotal Hit! - " + indicator)
                for scan in scans:
                    data = json_response['scans'][scan]
                    if(data['detected'] == True):
                        positivescanners.append(scan)
            if(remaining == 0):
                continue
            time.sleep(17)
        if(len(naughtylist) == 0):
            templist = []
            naughtylist.append(templist)
        naughtylist.append(score1)
        naughtylist.append(errorlist)  
        return(naughtylist)

    def VirusTotalIPv6(self,noreserved6):
        score2 = self.score
        iocs1 = self.iocs
        return(score2)

    # This funtion checks if the local and remote ports are both high.    
    def PortHeuristics(self,ports):
        score1 = self.score
        suspiciousports = []
        # Iterate through port pairs and append if both high
        for portset in ports:
            port1 = portset[0] 
            port2 = portset[1]
            if(int(port1) > 10000 and int(port2) > 10000):
                score1 = score1 + 2
                suspiciousports.append(portset)
        multiple = []
        # multiply ports together and append to list, set() will not work so hacky alternative
        uniquesuspiciousports = []
        for ports in suspiciousports:
            answer = int(ports[0]) * int(ports[1])
            if answer not in multiple:
                multiple.append(answer)
                uniquesuspiciousports.append(ports)
        returnlist = []
        returnlist.append(uniquesuspiciousports)
        returnlist.append(score1)    
        return(returnlist)

    # This function compares ports to the dictionary located in the function to check for known protocols. The dictionary can be added to.
    def ProtocolSummary(self,ports):
        protos = {'FTPD':20,'FTP':21,'SSH':22,'TELNET':23,'SMTP':25,'DNS':53,'HTTP':80,'KERBEROS':88,'IRC':194,'HTTPS':443,'SMB':445,'RDP':3389}
        #print(protos)
        portlist = []
        protocols = []
        for portset in ports:
            for port in portset:
                portlist.append(port)
        portlist = set(portlist)
        for key, value in protos.items():
            for port in portlist:
                port = int(port)
                if(port == value):
                    protocols.append(key)
        returnvalue = []
        underportlist = []
        for port in portlist:
            if(int(port) < 5000):
                underportlist.append(port)
        returnvalue.append(protocols)
        returnvalue.append(underportlist)
        return(returnvalue)
        
    # This function uses the extracted tls versions, checks if they are one of the versions listed
    # and will assign a score dependant on the version; the older the version the higher the score.
    def TLSHeuristics(self, tlstraffic):
        score3 = self.score
        SSLv3 = "0x0300"
        TLSv1 = "0x0301"
        TLSv11 = "0x0302"
        TLSv12 = "0x0303"
        protocols = [SSLv3, TLSv1, TLSv11, TLSv12]
        inuse = []
        #print(tlstraffic)
        for version in tlstraffic:
            if(version == "0x0300"): 
                score3 = score3 + 5
                inuse.append('SSLv3')
            if(version == "0x0301"): 
                score3 = score3 + 2
                inuse.append('TLSv1')
            if(version == "0x0302"): 
                score3 = score3 + 1
                inuse.append('TLSv1.1')
            if(version == "0x0303"):
                inuse.append('TLSv1.2')
            if(version not in protocols):
                score3 = score3 + 100
                inuse.append(version)
        returnlist = []
        #print(inuse)
        inuse = set(inuse)
        for proto in inuse:
            returnlist.append(proto)
        returnlist.append(score3)
        return(returnlist)
    
    # Compares a list of the IP addresses connected to and those returned via DNS
    # return any IP connected to not acquired via DNS from the pcap
    def nodnsconnect(self,domains,ips):
        score = 0
        dnsip = domains
        ipconnections = ips
        naughtylist = []
        for ip in ipconnections:
            if ip not in dnsip:
                naughtylist.append(ip)
                score = score + 50
        naughtylist.append(score)
        return(naughtylist)


    # Query alexa for the domains given to this function
    def Alexa(self, domains):
        total = len(domains)
        #domains = []
        score = 0
        errorlist = []
        lowlist = []
        counter = 1
        # Check Internet Connection
        try:
            r = requests.get("http://data.alexa.com/data?cli=10&dat=s&url=www.google.com", timeout=1)
        except ConnectionError as e:
            print("No Internet Connection, Skipping Alexa Function...")
            return False
        # Query each domain
        for domain in domains:
            send = "http://data.alexa.com/data?cli=10&dat=s&url=" + domain
            r = requests.get(send)
            r.encoding = 'utf-8'
            r = r.text
            remaining = total - counter
            print("Querying Alexa for Domain Rank...")
            print(str(remaining) + " Domains remaining...")
            # Manipulation of HTTP response as no API
            try:
                r = r.split('<REACH RANK="')
                r = r [1]
                r = r.split('"/><RANK DELTA')
                rank = r[0]
                rank = int(rank)
                if(rank > 100000):
                    score = score + 10
                    lowlist.append(domain)
            except IndexError:
                print("Unranked Domain")
                errorlist.append(domain)
                counter = counter + 1
                score = score + 10
                time.sleep(2)
                continue
            counter = counter + 1
            time.sleep(2)
        lowlist.append(score)
        lowlist.append(errorlist)
        return(lowlist)

    # Compare list of servers DNS requests were made to with those the hunter believes the whitelisted servers to be
    def DNSServerConnect(self,servers,requests):
        score1 = self.score
        dnsrequests = []
        for ip in requests:
            if ip not in servers:
                dnsrequests.append(ip)
                score1 = score1 + 50
        dnsrequests.append(score1)
        return(dnsrequests)

##################################################
# The following sectio of code is responsible calling functions, interpreting and manipulating results and
# creating the framework report.

#Heuristics Class Object
heur = heuristics()
#Processing Class Object
proc = extract()

#List of the files in temp which were cleaned at the beginning
filelist = proc.functionstocall()

# Initialising lists and variables for the for loop which will be outputted to the report.  
# The for loop will call functions based on the files detected in tempfile.
# The for loop follows the following method
# - Call Processing funtion
# - Call heuristics function with the processing function return value as an argument
# - Manipulate the return list from the heuristics function extracting the error list, naughty list and score
# - Set variables or add to lists which will be printed to report

scorelist = []
overallscore = 0
VTerrorlist = []
errorlist = []
naughtylist = []
lowlist = []
alexaerrorLIST = []
tlsinuse = []
highports = []
DGALIST1 = []
DGAlong = []
naughtyns = []
nodnslist = []
filehash = ''
protocolsdetected = ""
portsdetected = ""

for file in filelist:
    if "TLS" in file:
        # Call TLS Processing Function
        tlstraffic = proc.TLS()
        # Call TLS heuristics function with the processed list above as an argument
        tlsLIST = heur.TLSHeuristics(tlstraffic)
        # Extract score from returned list of results 
        tlsSCORE = tlsLIST[-1]
        del tlsLIST[-1]
        # List of TLS versions in use to print in report
        tlsINUSE = tlsLIST
        tlsinuse.append(tlsINUSE)
        # Append the below to a list to print in the report
        tlsprint = "TLS Score: " + str(tlsSCORE)
        scorelist.append(tlsprint)
        # Add TLS score to the overall total
        overallscore = overallscore + tlsSCORE
    if "DNS" in file:
        # DNS processing funtion
        domains = proc.DNS()
        # VirusTotal function for domains
        dnsLIST = heur.VirusTotal(domains,"Domains")
        # VT errors 
        dnserrorLIST = dnsLIST[-1]
        for error in dnserrorLIST:
            VTerrorlist.append(error)
        # Remove the vt errors to clean list 
        del dnsLIST[-1]
        # DNS score is next to extract from the results list
        dnsSCORE = dnsLIST[-1]
        del dnsLIST[-1]
        # Remaining in list is naughty domains
        dnsLIST = dnsLIST
        if(dnsLIST[-1] == 0):
            del dnsLIST[-1]
        dnsprint = "DNS VirusTotal Check Score: " + str(dnsSCORE)
        scorelist.append(dnsprint)
        # Add DNS VT score to overall
        overallscore = overallscore + dnsSCORE
        # Append the list of positive IoC to naughtylist to print in report along with other VT positives from IP
        naughtylist.append(dnsLIST)
        # Alexa function called
        alexa = heur.Alexa(domains)
        # If Alexa function returns nothing, set some variables to blank to stop errors
        if(alexa == False):
            alexaerror = ""
            alexaSCORE = 0
            alexa = ""
            alexabadLIST = alexa
        else:
            # manipulate the results list to extract errors, positive hits and score.
            alexaerror = alexa[-1]
            del alexa[-1]
            alexaSCORE = alexa[-1]
            del alexa[-1]
            alexabadLIST = alexa
            alexaerrorLIST.append(alexaerror)
        overallscore = overallscore + alexaSCORE
        lowlist.append(alexabadLIST)
        alexaprint = "Alexa Ranking Score: " + str(alexaSCORE)
        scorelist.append(alexaprint)
        # DGA function called
        DGALIST = heur.DGA(domains)
        DGAscore = DGALIST[-1]
        overallscore = overallscore + DGAscore
        dgaprint = "DGA Score: " + str(DGAscore)
        scorelist.append(dgaprint)
        del DGALIST[-1]
        DGAlong = DGALIST[-1]
        del DGALIST[-1]
        DGALIST1 = DGALIST
        
    if "SND" in file:
        # Calling function for DNS processing
        domains2 = proc.DNS2()
        # Calling the function to check if connnections have been made to IPs circumventing DNS
        connectwithnodns = heur.nodnsconnect(domains2,noreserved4)
        connectwithnodnsSCORE = connectwithnodns[-1]
        connectwithnodnsLIST = connectwithnodns
        if(connectwithnodnsLIST != 0):
            del connectwithnodnsLIST[-1]
        nodnslist =  connectwithnodnsLIST
        sndprint = "Connect with no DNS score: " + str(connectwithnodnsSCORE)
        overallscore = overallscore + connectwithnodnsSCORE
        scorelist.append(sndprint)

    if "IPv4" in file:
        # Call IPv4 processing function
        noreserved4 = proc.Gen4()
        # Call the VT function this time with IPs 
        gen4LIST = heur.VirusTotal(noreserved4,"IP Addresses")
        gen4LIST = gen4LIST
        # If nothing returned set variables so errors do not occur.
        if(gen4LIST == False):
            gen4errorLIST = ""
            gen4SCORE = 0
            gen4LIST = ""
        else:
            gen4errorLIST = gen4LIST[-1]
            for error1 in gen4errorLIST:
                VTerrorlist.append(error1)
            del gen4LIST[-1]
            gen4SCORE = gen4LIST[-1]
            del gen4LIST[-1]
            gen4LIST = gen4LIST
            if(gen4LIST != 0):
                del gen4LIST[-1]
        ip4print = "IP VirusTotal Check Score: " + str(gen4SCORE)
        scorelist.append(ip4print)
        overallscore = overallscore + gen4SCORE
        naughtylist.append(gen4LIST)

    if "IPv6" in file:
        noreserved6 = proc.Gen6()

    if "Port" in file:
        ports = proc.Port()
        #Protocol Summary
        protosum = heur.ProtocolSummary(ports)
        protocolsdetected = protosum[0]
        portsdetected = protosum[1]
        portsdetected = sorted(portsdetected, key=int)
        #Two High Ports
        portheur = heur.PortHeuristics(ports)
        portscore = int(portheur[1])
        badports = portheur[0]
        highports.append(badports)
        portprint = "High Ports Score: " + str(portscore)
        scorelist.append(portprint)
        overallscore = overallscore + portscore

    # Filename of inputted pcap from main.
    if "filename" in file:
        filename = file
        filename = filename.split(sep="-")
        pcapfilename = filename[-1]
        pcap1 = pcapfilename.split(sep="/")
        pcap1 = pcap1[-1]
        filen = pcap1.split(sep=".")
        filen = filen[0]
        print("Performing Analysis on: " + pcap1)

    # This section calls the functions to compare the list of IP addresses DNS requests are made to with
    # the list of whitelisted ip addresses given in main.py
    if "NameServer" in file:
        requestips = proc.DNS3()
        filename = file
        cutdown = filename.split(sep="-") 
        nameservers = cutdown[1]
        nameserverlist = []
        nameservers = nameservers.split(",")
        for ns in nameservers:
            ns = "".join(ns.split())
            nameserverlist.append(ns)
        nsreturn = heur.DNSServerConnect(nameserverlist,requestips)
        nsscore = nsreturn[-1]
        del nsreturn[-1]
        naughtyns = nsreturn
        nsprint = "DNS Request to non-designated Server Score: " + str(nsscore)
        scorelist.append(nsprint)
        overallscore = overallscore + nsscore

    # extract hash of inputted pcap for report
    if "Filehash" in file:
        filehash = file
        filehash = filehash.split(sep="-")
        filehash = filehash[1]      

#
naughtylist = [val for sublist in naughtylist for val in sublist]
errorlist = [val for sublist in errorlist for val in sublist]

#
lowlist = [val for sublist in lowlist for val in sublist]
alexaerrorLIST = [val for sublist in alexaerrorLIST for val in sublist]

# Convert some list variables into strings so they can be printed to report
naughtylist = str(naughtylist)
VTerrorlist = str(VTerrorlist)
lowlist = str(lowlist)
alexaerrorLIST = str(alexaerrorLIST)
protocolsdetected = str(protocolsdetected)
lowlist = str(lowlist)
DGALIST1 = str(DGALIST1)
DGAlong = str(DGAlong)
portsdetected = str(portsdetected)
nodnslist = str(nodnslist)
naughtyns = str(naughtyns)

# Cleaning some lists of characters before they are printed.
charstodelete = dict.fromkeys(map(ord, "[]'"), None)

lowlist = lowlist.translate(charstodelete)
DGALIST1 = DGALIST1.translate(charstodelete)
DGAlong = DGAlong.translate(charstodelete)
alexaerrorLIST = alexaerrorLIST.translate(charstodelete)
naughtylist = naughtylist.translate(charstodelete)
VTerrorlist = VTerrorlist.translate(charstodelete)
protocolsdetected = protocolsdetected.translate(charstodelete)
portsdetected = portsdetected.translate(charstodelete)
nodnslist = nodnslist.translate(charstodelete)
naughtyns = naughtyns.translate(charstodelete)

if(naughtylist == ', '):
    naughtylist = ''

# If the OS running script is linux then retrieve some data about the pcap

operating = sys.platform
if 'linux' in operating:
    cmd = 'capinfos -a -e "{0}"'.format(pcapfilename) # 
    start = os.popen(cmd).read()
    end = start.split('\n')
    del end[0]
    start = str(end[0])
    end = str(end[1])
else:
    start = ""
    end = ""

# Create some variables for the report
# Name and location of output report
outfile = "Output/" + filen + "-Report.txt"
overalloutput = "Overall Score: " + str(overallscore)
filename = "Analysis conducted on " + pcapfilename
date = "Time and Date of Analysis was " + datetime.datetime.now().strftime('%H:%M:%S %d/%m/%Y ')
f = open(outfile,'w')
f.write("")
f.close()

# The below is where the report is produced
f = open(outfile,'a')
f.write("___________________Report Start___________________\n\n")
f.write(filename + "\n")
f.write(date)
f.write("\n\n")
f.write(start)
f.write("\n")
f.write(end)
f.write("\n\n")
f.write(overalloutput)
f.write("\n\n")
f.write("SHA256 Hash of file: " + filehash)
f.write("\n\n")
f.write("Score Breakdown:\n")
for score in scorelist:
    f.write(" - " + score + "\n")
f.write("\nProtocols Detected: " + str(protocolsdetected))
f.write("\n\n")
f.write("\nIndicators Of Compromise Detected by VirusTotal:\n")
f.write(naughtylist)
f.write("\n")
f.write("\nDomains and IP Addresses which returned errors in VirusTotal, therefore require manual investigation:\n")
f.write(VTerrorlist)
f.write("\n\n")
f.write("\nLow Ranking Domains Detected by Alexa:\n")
f.write(lowlist)
f.write("\n\n")
f.write("\nDomains and IP Addresses which did not rank in Alexa:\n")
f.write(alexaerrorLIST)
f.write("\n\n")
f.write("TLS Versions Detected: \n")
for item in tlsinuse:
    item = str(item)
    item = item.translate(charstodelete)
    f.write(item)
f.write("\n\n")
f.write("List of domains over 25 characters in length: \n")
f.write(str(DGAlong))
f.write("\n\n")
f.write("List of DGA style domains: \n")
f.write(str(DGALIST1))
f.write("\n\n")
f.write("DNS Requests were made to these non-designated servers: \n")
f.write(str(naughtyns))
f.write("\n\n")
f.write("Connections were made to these IP Addresses without them being acquired via DNS: \n")
f.write(str(nodnslist))
f.write("\n\n")
f.write("Ports Detected (under 5000): " + str(portsdetected))
f.write("\n\n")
f.write("High Port Pairs: \n")
for port in highports:
    port = str(port)
    port = port.translate(charstodelete)
    f.write(port)
f.write("\n\n")
f.write("___________________Report End_____________________\n")
f.close()
print("Report outputted: " + outfile)    
