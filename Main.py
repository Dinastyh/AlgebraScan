from sys import argv
from tcp.TcpScan import tcpManager
from arp.ArpScan import arpScan
from icmp.IcmpScan import icmpScan
from udp.UdpScan import udpManager
import ipaddress

def main():

    data = argv[1]
    ips=[]
    if "-" in data:
        dataSplit = data.split("-")
        ip1 = dataSplit[0].split(".")
        ip2= dataSplit[1].split(".")
        #check enter

        if int(ip1[3]) > int(ip2[3]):
            ip1, ip2 = ip2, ip1
        startIp = ip1[0]+"."+ip1[1]+"."+ip1[2]+"."
        for i in range(int(ip1), int(ip2)+1):
            ips.append(startIp+str(i))
    elif "/" in data:
        net4 = ipaddress.ip_network(data)
        ips+=net4.hosts()
    else:
        ips.append(data)

    if argv[2] in ["-a","--arp"]:
        arpScan(ips)
    elif argv[2] in ["-i", "--icmp"]:
        icmpScan(ips)
    elif argv[2] in ["-t", "--tpc"]:
        tcpManager(argv[3:], ips)
    elif argv[2] in ["-u", "--udp"]:
        udpManager(argv[3:], ips)


if __name__ == "__main__":
    main()
