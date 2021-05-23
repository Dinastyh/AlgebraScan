from scapy.all import ARP, Ether, srp

def arpScan(ips):
    arp = ARP(pdst=ips)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3)[0]
    data=[]
    for sent, received in result:
        id = (15-len(received.psrc))*" "
        print('IP: ' +received.psrc+id+"    "+ 'MAC: ' +received.hwsrc)