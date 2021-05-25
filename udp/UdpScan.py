from scapy.all import IP, UDP, sr, ICMP

def udpManager(args, ips):
    #Port Paser
    if len(args) > 1:
        data = args[1].split(",")
        port = []
        for i in data:
            if "-" in i:
                iSplit = i.split("-")
                if len(iSplit) == 1:
                    #Gestion of interval defined by -X or X-
                    if i[0] == "-":
                        port += [i for i in range(0,int(iSplit[0])+1)]
                    else:
                        port += [i for i in range(int(iSplit[0]), 64739)]
                else:
                    #Check if interval is correct
                    if int(iSplit[0]) > int(iSplit[1]):
                        iSplit[0], iSplit[1] = iSplit[1], iSplit[0]
                    port += [i for i in range(int(iSplit[0]), int(iSplit[1])+1)]
            else:
                port.append(int(i))
            #Delete double and sort port
            port = list(set(port))
            port.sort()
    else:        
        port=[i for i in range(0, 101)]

    for i in ips:
        udpScan(i, port)
        



def udpScan(ip, ports, timeout=1):
    results = {port:None for port in ports}

    #Build packet
    p = IP(dst=ip)/UDP(sport=ports, dport=ports)
    answers= sr(p, timeout=timeout, verbose=0)[0]

    #Analyse data

    for resp in answers[1]:
        if resp.haslayer(ICMP):
            results[resp.sport] = False
        elif resp.haslayer(UDP):
            results[resp.sport] = True

        
    print("======= Result for Udp Scan of "+str(ip)+"=======")
    for k,v in results.items():
        if v != None:
            print(str(k) + " -> " + str(v))


    #Make possible to use results as data
    return results