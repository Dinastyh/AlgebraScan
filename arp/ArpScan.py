from scapy.all import ARP, Ether, srp

def arpScan(ips):
    #Packet Construction
    arp = ARP(pdst=ips)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    #Send of packet 
    result = srp(packet, timeout=3, verbose=0)[0]

    #Result display
    print("======= Result for Arp Scan=======")
    for sent, received in result:
        id = (15-len(received.psrc))*" "
        print('IP: ' +received.psrc+id+"    "+ 'MAC: ' +received.hwsrc)