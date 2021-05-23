from scapy.all import IP, TCP, sr
import socket

def tcpManager(args, ips):
    data = args.split(",")
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
        tcpScan(port)



def tcpScan(ip, ports):
    try:
        syn = IP(dst=ip) / TCP(dport=ports, flags="S")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))


    ans, unans = sr(syn, timeout=2, retry=1)
    result = []

    for sent, received in ans:
        if received[TCP].flags == "SA":
            result.append(received[TCP].sport)

    return result