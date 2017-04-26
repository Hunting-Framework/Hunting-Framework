# Modules to be imported from libraries
import os
import sys
import datetime
import csv
import hashlib

# The purpose of this script is to extract specified data from a pcap file and output this data to multiple
# csv files for analysis by the next script. It also creates a temporary file which it stores filenames and
# other data in for collection by the next script, heur.py

#Location where .py script is
start = os.getcwd()


class TsharkExtract:
    pcap = sys.argv[1] # Pcap Name
    output = datetime.datetime.now().strftime('%Y-%m-%d-%H-%M-%S') + ".csv" # Defining an output filename based on time
    
    if(os.path.isfile(pcap) != True): #Does Input file exist?
        print("Cannot find pcap file.")
        exit()

    if(len(sys.argv) != 2):
        print("Incorrect number of arguments given.\n")
        print("usage: python3 Main.py <pcap>\n")
        exit()

    if not os.path.exists("Output/"):
        os.makedirs("Output/")    
    #Clean/Create Temp File
    f = open('Output/tempfile.temp','w')
    f.write("")
    f.close()
    f = open('Output/tempfile.temp','a')
    f.write("filename-" + pcap + "\n")
    f.close()
    # Function for extracting general data from pcap

    def General(self):
        genout = "General" + self.output
        genout4 = "IPv4" + genout
        genout6 = "IPv6" + genout
        genport = "Port" + genout
        # Below are the tshark commands which are executed
        cmd4 = 'tshark -E separator="," -r "{0}" -T fields -e ip.src -e ip.dst  -e ip.len -e dns.qry.name -e ip.proto -e tcp.port -e udp.port > "Output/{1}"'.format(self.pcap,genout4)
        os.system(cmd4) # Call above command
        cmd6 = 'tshark -E separator="," -r "{0}" -T fields -e ipv6.src -e ipv6.dst  -e ip.len -e dns.qry.name -e ip.proto -e tcp.port -e udp.port > "Output/{1}"'.format(self.pcap,genout6)
        os.system(cmd6)
        cmdport = 'tshark -E separator="," -r "{0}" -T fields -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport> "Output/{1}"'.format(self.pcap,genport)
        os.system(cmdport)
        print("General CSV Outputted for analysis")
        
        #Print Filename Out to 
        f = open('Output/tempfile.temp','a')
        genout4 = genout4 + "\n"
        genout6 = genout6 + "\n"
        genoutport = genport + "\n"
        f.write(genout4)
        f.write(genout6)
        f.write(genoutport)
        f.close()

        
    def DNS(self):
        dnsout = "DNS" + self.output
        sndout = "SND" + self.output
        dnsip = "DNIPS" + self.output
        # Tshark Commands for DNS data
        cmd = 'tshark -E separator="," -r "{0}" -T fields -e dns.qry.name -e dns.a > "Output/{1}"'.format(self.pcap,dnsout)
        cmd1 = 'tshark -E separator="," -r "{0}" -T fields -e dns.resp.addr > "Output/{1}"'.format(self.pcap,sndout)
        cmd3 = 'tshark -E separator="," -r "{0}" -T fields -e dns.flags.response -e ip.addr -e ipv6.src -e ipv6.dst > "Output/{1}"'.format(self.pcap,dnsip)
        # Call Tshark commands
        os.system(cmd)
        os.system(cmd1)
        os.system(cmd3)
        print("DNS CSV Outputted for analysis")

        # Appending to Temp File
        dnsout = dnsout + "\n"
        sndout = sndout + "\n"
        dnsip = dnsip + "\n"
        f = open('Output/tempfile.temp','a')
        f.write(dnsout)
        f.write(sndout)
        f.write(dnsip)
        f.close()
        
    def TLS(self):
        tlsout = "TLS" + self.output
        cmd = 'tshark -E separator="," -r "{0}" -T fields -e ssl.handshake.version -e ssl.handshake.ciphersuite > "Output/{1}"'.format(self.pcap,tlsout)
        os.system(cmd)
        print("TLS CSV Outputted for analysis")
        
        # Appending Filename To Temp File
        f = open('Output/tempfile.temp','a')
        f.write(tlsout)
        f.close()


    def DNSserver(self):
        # Used to determine if DNS requests are sent to correct destination
        server = input("Please input the DNS Server's IP Address for the network, multiple server IP addresses can be used (separated by a comma) or it can be left blank: ")
        if(server == ""):
            print("No DNS Server entered, continuing...")
        else:
            # Write nameserver IPs to temp file for collection in next script
            server = "NameServer-" + server + "\n"
            # Appending Filename To Temp File
            f = open('Output/tempfile.temp','a')
            f.write(server)
            f.close()

    # This funtion hashes the pcap file inputted, appends it to temp file so that it can be included in the report
    def Hash(self):
        pcap = self.pcap
        blocksize = 65536
        sha256 = hashlib.sha256()
        with open(pcap, 'rb') as hashfile:
            for block in iter(lambda: hashfile.read(blocksize), b''):
                sha256.update(block)
            filehash = sha256.hexdigest()
        filehash = "Filehash-" + filehash + "\n"
        f = open('Output/tempfile.temp','a')
        f.write(filehash)
        f.close()
        

# Define object
extract = TsharkExtract()

#Call functions
extract.DNSserver()
extract.Hash()
extract.General()
extract.DNS()
extract.TLS()

# End of Code
