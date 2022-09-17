import os
import sys
import re
import dns.resolver
import time

dnsservers = ['172.98.193.42','208.67.220.220','198.50.135.212','45.76.254.23','172.98.193.62','198.74.48.37','1.1.1.1','46.21.150.56','208.67.222.123','208.67.222.222','1.0.0.1','185.228.168.9','185.228.169.9','76.76.19.19','76.223.122.150']
badservers = []
i = 0
syslog=tls=arin = 0
f=r=serverstr = ''
s = []
commands = ['-f', '-tls', '-r', '-s', '-arin']
servercount = 0
servers = len(dnsservers)
ipregex = re.compile(r'[0-9]+(?:\.[0-9]+){3}', re.IGNORECASE)
linebreak = '========================================'
def ptrq(ip,method):
    global servercount
    global dnsservers
    global servers
    global badservers
    success = False
    dnsResolver = dns.resolver.Resolver()
    if dnsservers[servercount] in badservers:
        findnextdns(ip,method)
    dnslst = [dnsservers[servercount]]
    dnsResolver.nameservers = dnslst

    try:
        if tls:
            #answer = dnsResolver.resolve.tls(dns.reversename.from_address(ip),'PTR')
            #answerSOA = dnsResolver.resolve.tls(dns.reversename.from_address(ip), 'SOA',raise_on_no_answer=False)
            print("TLS Not implemented yet.")
            exit()
        else:
            answer = dnsResolver.query(dns.reversename.from_address(ip),'PTR')
            answerSOA = dnsResolver.query(dns.reversename.from_address(ip), 'SOA',raise_on_no_answer=False)

        print(ip)
        for rdata in answer:
            print(rdata)
        try:
            ansshort = answerSOA.response.authority[0].to_text()
            print(ansshort[ansshort.index('IN SOA ') + 7:ansshort.rindex('.') + 1])
            print('Used Resolver: ' + dnsservers[servercount])
        except IndexError:
            print("No SOA info Available")
        success = True
        if not arin:
            print(linebreak)
    except dns.exception.Timeout:
        print('DNS server timeout, trying next server.')
        badservers.append(dnsservers[servercount])
        findnextdns(ip,method)
        
    except dns.resolver.NoNameservers:
        print('Broken Name Server for ' + ip)     
        
    except dns.resolver.NXDOMAIN:
        print('Domain not available for ' + ip)
        if not arin:
            print(linebreak)
        success = True
    if servercount + 1 == servers:
        servercount = 0
    else:
        servercount += 1  
    if arin and success == True:
        arinfetch(ip,0)
        print(linebreak)
             

def findnextdns(inip,method):
    global servercount
    loopstart = servercount
    global dnsservers
    global servers

    if servers == 1:
        print("No remaining DNS servers, all marked as offline")
        exit()
    elif servercount + 1 >= servers:
        servercount = 0
    else:
        servercount += 1

    while dnsservers[servercount] in badservers:
        
        if servercount + 1 >= servers:
            servercount = 0
        else:
            servercount += 1
        if servercount == loopstart:
            print("No remaining DNS servers, all marked as offline")
            exit()
    ptrq(inip,method)

def arinfetch(ip,retry):
    
   if retry == 0:
       try:
           r = requests.get('https://whois.arin.net/rest/ip/' + ip + '.txt')
           lines = r.text.split('\n')
           for line in lines:
               if 'NetRange' in line or 'NetName' in line or 'Organization' in line:
                   print(line)
       except requests.exceptions.ConnectionError:
           print('Connection to Arin closed... Trying again in 5s')
           time.sleep(5)
           arinfetch(ip,1)
   elif retry == 1:
       try:
           r = requests.get('https://whois.arin.net/rest/ip/' + ip + '.txt')
           lines = r.text.split('\n')
           for line in lines:
               if 'NetRange' in line or 'NetName' in line or 'Organization' in line:
                   print(line)
       except requests.exceptions.ConnectionError:
           print('Still cannot connect to Arin... Trying again in 10s')
           time.sleep(10)
           arinfetch(ip,2)
   elif retry == 2:
       print("Cannot connect at this time")
         
         


args = sys.argv[1:]
c=0
for arg in args:
    if arg == '-f':
        try:
            if args[c+1] in commands:
                print("-f requires a filename")
                exit()
            else:
                f = args[c+1]
                
        except IndexError:
            print("Reached end of line, -f requires a filename")
            exit()
      
    elif arg == '-tls':
        tls = 1
    elif arg == '-r':
        try:
            if args[c+1] in commands:
                print("-r requires a valid IP as an argument x.x.x.x-x")
                exit()
            else:
                r = args[c+1]
                
        except IndexError:
            print("Reached end of line, -r requires an IP range x.x.x.x-x")
            exit()
    elif arg == '-s':
        try:
            if args[c+1] in commands:
                print("-s requires a server or list of servers separated by \',\' ")
                exit()
            else:
                serverstr = args[c+1]
                
                dnsservers = serverstr.split(',')
                servers = len(dnsservers)
                for server in dnsservers:
                    if not ipregex.match(server):
                        print('Error, Please enter a valid DNS server by IPv4 address')
                        exit()
                        
        except IndexError:
            print("Reached end of line, -s requires a server or list of servers separated by \',\' ")
            exit()
    elif arg == '-arin':
        print("Warning, too many requests might piss them off")
        import requests
        arin = 1
    elif arg == '-h' or arg == '-help' or arg == '-?':
        print('Usage:')
        print('Returns list of PTR and SOA records for reverse ordered IP addresses specified as a range or found in a file.')
        print('    -r x.x.x.x-x        Provide range of ip addresses to lookup')
        print('    -s x.x.x.x,x.x.x.x  Provide list of DNS servers to question separated by comma')
        print('    -tls                Enable tls protected DNS lookup, not implemented yet')
        print('    -f /path/to/file    Use Regex based matching to locate IP addresses in a file')
        print('    -arin               Queries ARIN for IP address information relating to Orgname and AS')
        
    c = c + 1
    
 
 
 
 
    
if r:
    rng = 0
    octets = r.split('.')
    if len(octets) != 4:
        print("Error, Please enter a valid IP address\n")
        exit()
    rngfinder = 0
    for octet in octets:
        if '-' in octet:
            break
        else:
            rngfinder += 1
    if rngfinder == 4:
        if octets[3] == "0":
            pass
        else:
            ptrq(r,tls)
    else:
        rngf = octets[rngfinder]
        left = int(rngf[:rngf.index('-')])
        right = int(rngf[rngf.index('-') + 1:])
        if rngfinder == 3:
            for i in range((right - left) + 1):
                if left + i == 0:
                    pass
                else:
                    ptrq(octets[0] + '.' + octets[1] + '.' + octets[2] + '.' + str(left + i),tls)
        elif rngfinder == 2:
            c = 0
            d = int(octets[3])
            while(left + c != right or d !=256):
                if d == 256:
                    d = 0
                    c += 1
                if d == 0:
                    pass
                else:
                    ptrq(octets[0] + '.' + octets[1] + '.' + str(left + c) + '.' + str(d),tls)           
                d+=1
        elif rngfinder == 1:
            b = 0
            c = int(octets[2])
            d = int(octets[3])
            while(not ((left + b == right) and (c == 255) and (d==256)) ):
                if d == 256:
                    d = 0
                    c += 1
                if c == 256:
                    c = 0
                    b +=1
                if d == 0:
                    pass
                else:
                    ptrq(octets[0] + '.' + str(left + b) + '.' + str(c) + '.' + str(d),tls)           
                d+=1
        elif rngfinder == 0:
            print("loco")
            a = 0
            b = int(octets[1])
            c = int(octets[2])
            d = int(octets[3])
            while(not ((left + a == right) and (b == 255) and (c == 255) and (d == 256))):
                if d == 256:
                    d = 0
                    c += 1
                if c == 256:
                    c = 0
                    b += 1
                if b == 256:
                    b = 0
                    a += 1
                if d == 0:
                    pass
                else:
                    ptrq(str(left + a) + '.' + str(b) + '.' + str(c) + '.' + str(d),tls)
                d+=1
        else:
            print("Error, Please enter a correct IP address")
            
            
            
            

if f:
    iplist = []
    ipliststr = ''
    pfile = open(f,'r')
    pfilecontent = pfile.readlines()
    for line in pfilecontent:
        
        linelist = ipregex.findall(line)
        if linelist:
            for ip in linelist:
                if ip not in ipliststr:
                    ipliststr = ipliststr + ip + ','
                    iplist.append([ip,1])
                else:
                    for ipelement in iplist:
                        if ip in ipelement[0]:
                            ipelement[1] +=1
    iplist = sorted(iplist,key=lambda l:l[1], reverse=True)
    for addr in iplist:
        ptrq(addr[0],tls)
    pfile.close()
                    
    
    
        
print(badservers)         

                
            
        
    
    
    
                
                
