from sys import argv
from tcp.TcpScan import tcpManager
from arp.ArpScan import arpScan
from icmp.IcmpScan import icmpScan
from udp.UdpScan import udpManager
from netaddr import IPNetwork

def main():
    
    #Parser ip
    data = argv[1]
    if len(argv)<2 or not "." in data:
        print("Bad Usage")
        print("sudo python Main.py <ip> <modes> <args>")
        return

    ips=[]
    if "-" in data:
        dataSplit = data.split("-")
        ip1 = dataSplit[0].split(".")
        ip2= dataSplit[1].split(".")

        #Check if interval is correct
        if int(ip1[3]) > int(ip2[3]):
            ip1, ip2 = ip2, ip1


        startIp = ip1[0]+"."+ip1[1]+"."+ip1[2]+"."
        for i in range(int(ip1[3]), int(ip2[3])+1):
            ips.append(startIp+str(i))

    elif "/" in data:
        #SubNet gestion
        net4 = IPNetwork(data)
        for i in net4:
            ips.append(format(i))
    else:
        ips.append(data)


    #Select Mode Scan

    if argv[2] in ["-a","--arp"]:
        arpScan(ips)
    elif argv[2] in ["-i", "--icmp"]:
        icmpScan(ips)
    elif argv[2] in ["-t", "--tcp"]:
        tcpManager(argv[3:], ips)
    elif argv[2] in ["-u", "--udp"]:
        udpManager(argv[3:], ips)
    else:
        print("Mode not found")
        print("Please choose one in: -a/--arp, -i/--icmp, -t/--tcp or -u/--udp")

if __name__ == "__main__":
    main()
