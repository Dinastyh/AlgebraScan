from scapy.all import IP, TCP, sr
import socket

def tcpManager(args, ips):
    if len(args) > 0:
        data = args[0].split(",")
        port = []
        for i in data:
            if "-" in i:
                iSplit = i.split("-")
                if len(iSplit) == 1:
                    if i[0] == "-":
                        port += [i for i in range(0,int(iSplit[0])+1)]
                    else:
                        port += [i for i in range(int(iSplit[0]), 64739)]
                else:
                    if int(iSplit[0]) > int(iSplit[1]):
                        iSplit[0], iSplit[1] = iSplit[1], iSplit[0]
                    port += [i for i in range(int(iSplit[0]), int(iSplit[1]))]
            else:
                port+= int(i)
            port = list(set(port))
            port.sort()
    else:        
        port=[i for i in range(0, 100)]

    for i in ips:
        tcpScan(i, port)
        



def tcpScan(ip, ports, timeout=1):
    results = {port:None for port in ports}

    p = IP(dst=ip)/TCP(sport=ports,dport=ports, flags='S')
    answers, un_answered = sr(p, timeout=timeout, verbose=0)

    for req, resp in answers:
        if not resp.haslayer(TCP):
            continue
        tcp_layer = resp.getlayer(TCP)

        if tcp_layer.flags == 0x12:
            results[tcp_layer.sport] = True

        elif tcp_layer.flags == 0x14:
            results[tcp_layer.sport] = False
            
    print("======= Result for Tcp Scan of "+str(ip)+"=======")
    for k,v in results.items():
        if v != None:
            print(str(k) + " -> " + str(v))